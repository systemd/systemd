/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "device-private.h"
#include "device-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "id128-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-util.h"
#include "utf8.h"

static const char* const resolve_name_timing_table[_RESOLVE_NAME_TIMING_MAX] = {
        [RESOLVE_NAME_NEVER] = "never",
        [RESOLVE_NAME_LATE]  = "late",
        [RESOLVE_NAME_EARLY] = "early",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_name_timing, ResolveNameTiming);

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec,
                ResolveNameTiming *ret_resolve_name_timing,
                int *ret_timeout_signal) {

        _cleanup_free_ char *log_val = NULL, *children_max = NULL, *exec_delay = NULL, *event_timeout = NULL, *resolve_names = NULL, *timeout_signal = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/udev/udev.conf",
                           "udev_log", &log_val,
                           "children_max", &children_max,
                           "exec_delay", &exec_delay,
                           "event_timeout", &event_timeout,
                           "resolve_names", &resolve_names,
                           "timeout_signal", &timeout_signal);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        if (log_val) {
                const char *log;
                size_t n;

                /* unquote */
                n = strlen(log_val);
                if (n >= 2 &&
                    ((log_val[0] == '"' && log_val[n-1] == '"') ||
                     (log_val[0] == '\'' && log_val[n-1] == '\''))) {
                        log_val[n - 1] = '\0';
                        log = log_val + 1;
                } else
                        log = log_val;

                /* we set the udev log level here explicitly, this is supposed
                 * to regulate the code in libudev/ and udev/. */
                r = log_set_max_level_from_string(log);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set udev log level '%s', ignoring: %m", log);
        }

        if (ret_children_max && children_max) {
                r = safe_atou(children_max, ret_children_max);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to parse children_max=%s, ignoring: %m", children_max);
        }

        if (ret_exec_delay_usec && exec_delay) {
                r = parse_sec(exec_delay, ret_exec_delay_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to parse exec_delay=%s, ignoring: %m", exec_delay);
        }

        if (ret_event_timeout_usec && event_timeout) {
                r = parse_sec(event_timeout, ret_event_timeout_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to parse event_timeout=%s, ignoring: %m", event_timeout);
        }

        if (ret_resolve_name_timing && resolve_names) {
                ResolveNameTiming t;

                t = resolve_name_timing_from_string(resolve_names);
                if (t < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to parse resolve_names=%s, ignoring.", resolve_names);
                else
                        *ret_resolve_name_timing = t;
        }

        if (ret_timeout_signal && timeout_signal) {
                r = signal_from_string(timeout_signal);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to parse timeout_signal=%s, ignoring: %m", timeout_signal);
                else
                        *ret_timeout_signal = r;
        }

        return 0;
}

struct DeviceMonitorData {
        const char *sysname;
        const char *devlink;
        sd_device *device;
};

static void device_monitor_data_free(struct DeviceMonitorData *d) {
        assert(d);

        sd_device_unref(d->device);
}

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        struct DeviceMonitorData *data = ASSERT_PTR(userdata);
        const char *sysname;

        assert(device);
        assert(data->sysname || data->devlink);
        assert(!data->device);

        /* Ignore REMOVE events here. We are waiting for initialization after all, not de-initialization. We
         * might see a REMOVE event from an earlier use of the device (devices by the same name are recycled
         * by the kernel after all), which we should not get confused by. After all we cannot distinguish use
         * cycles of the devices, as the udev queue is entirely asynchronous.
         *
         * If we see a REMOVE event here for the use cycle we actually care about then we won't notice of
         * course, but that should be OK, given the timeout logic used on the wait loop: this will be noticed
         * by means of -ETIMEDOUT. Thus we won't notice immediately, but eventually, and that should be
         * sufficient for an error path that should regularly not happen.
         *
         * (And yes, we only need to special case REMOVE. It's the only "negative" event type, where a device
         * ceases to exist. All other event types are "positive": the device exists and is registered in the
         * udev database, thus whenever we see the event, we can consider it initialized.) */
        if (device_for_action(device, SD_DEVICE_REMOVE))
                return 0;

        if (data->sysname && sd_device_get_sysname(device, &sysname) >= 0 && streq(sysname, data->sysname))
                goto found;

        if (data->devlink) {
                const char *devlink;

                FOREACH_DEVICE_DEVLINK(device, devlink)
                        if (path_equal(devlink, data->devlink))
                                goto found;

                if (sd_device_get_devname(device, &devlink) >= 0 && path_equal(devlink, data->devlink))
                        goto found;
        }

        return 0;

found:
        data->device = sd_device_ref(device);
        return sd_event_exit(sd_device_monitor_get_event(monitor), 0);
}

static int device_wait_for_initialization_internal(
                sd_device *_device,
                const char *devlink,
                const char *subsystem,
                usec_t timeout_usec,
                sd_device **ret) {

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        /* Ensure that if !_device && devlink, device gets unrefd on errors since it will be new */
        _cleanup_(sd_device_unrefp) sd_device *device = sd_device_ref(_device);
        _cleanup_(device_monitor_data_free) struct DeviceMonitorData data = {
                .devlink = devlink,
        };
        int r;

        assert(device || (subsystem && devlink));

        /* Devlink might already exist, if it does get the device to use the sysname filtering */
        if (!device && devlink) {
                r = sd_device_new_from_devname(&device, devlink);
                if (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r))
                        return log_error_errno(r, "Failed to create sd-device object from %s: %m", devlink);
        }

        if (device) {
                if (sd_device_get_is_initialized(device) > 0) {
                        if (ret)
                                *ret = sd_device_ref(device);
                        return 0;
                }
                /* We need either the sysname or the devlink for filtering */
                assert_se(sd_device_get_sysname(device, &data.sysname) >= 0 || devlink);
        }

        /* Wait until the device is initialized, so that we can get access to the ID_PATH property */

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event: %m");

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire monitor: %m");

        if (device && !subsystem) {
                r = sd_device_get_subsystem(device, &subsystem);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(device, r, "Failed to get subsystem: %m");
        }

        if (subsystem) {
                r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add %s subsystem match to monitor: %m", subsystem);
        }

        _cleanup_free_ char *desc = NULL;
        const char *sysname = NULL;
        if (device)
                (void) sd_device_get_sysname(device, &sysname);

        desc = strjoin(sysname ?: subsystem, devlink ? ":" : ":initialization", devlink);
        if (desc)
                (void) sd_device_monitor_set_description(monitor, desc);

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(monitor, device_monitor_handler, &data);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        if (timeout_usec != USEC_INFINITY) {
                r = sd_event_add_time_relative(
                                event, NULL,
                                CLOCK_MONOTONIC, timeout_usec, 0,
                                NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0)
                        return log_error_errno(r, "Failed to add timeout event source: %m");
        }

        /* Check again, maybe things changed. Udev will re-read the db if the device wasn't initialized yet. */
        if (!device && devlink) {
                r = sd_device_new_from_devname(&device, devlink);
                if (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r))
                        return log_error_errno(r, "Failed to create sd-device object from %s: %m", devlink);
        }
        if (device && sd_device_get_is_initialized(device) > 0) {
                if (ret)
                        *ret = sd_device_ref(device);
                return 0;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for device to be initialized: %m");

        if (ret)
                *ret = TAKE_PTR(data.device);
        return 0;
}

int device_wait_for_initialization(sd_device *device, const char *subsystem, usec_t timeout_usec, sd_device **ret) {
        return device_wait_for_initialization_internal(device, NULL, subsystem, timeout_usec, ret);
}

int device_wait_for_devlink(const char *devlink, const char *subsystem, usec_t timeout_usec, sd_device **ret) {
        return device_wait_for_initialization_internal(NULL, devlink, subsystem, timeout_usec, ret);
}

int device_is_renaming(sd_device *dev) {
        int r;

        assert(dev);

        r = sd_device_get_property_value(dev, "ID_RENAMING", NULL);
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return r;

        return true;
}

bool device_for_action(sd_device *dev, sd_device_action_t a) {
        sd_device_action_t b;

        assert(dev);

        if (a < 0)
                return false;

        if (sd_device_get_action(dev, &b) < 0)
                return false;

        return a == b;
}

void log_device_uevent(sd_device *device, const char *str) {
        sd_device_action_t action = _SD_DEVICE_ACTION_INVALID;
        sd_id128_t event_id = SD_ID128_NULL;
        uint64_t seqnum = 0;

        if (!DEBUG_LOGGING)
                return;

        (void) sd_device_get_seqnum(device, &seqnum);
        (void) sd_device_get_action(device, &action);
        (void) sd_device_get_trigger_uuid(device, &event_id);
        log_device_debug(device, "%s%s(SEQNUM=%"PRIu64", ACTION=%s%s%s)",
                         strempty(str), isempty(str) ? "" : " ",
                         seqnum, strna(device_action_to_string(action)),
                         sd_id128_is_null(event_id) ? "" : ", UUID=",
                         sd_id128_is_null(event_id) ? "" : SD_ID128_TO_UUID_STRING(event_id));
}

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos) {
        char *i, *j;
        bool is_escaped;

        /* value must be double quotated */
        is_escaped = str[0] == 'e';
        str += is_escaped;
        if (str[0] != '"')
                return -EINVAL;
        str++;

        if (!is_escaped) {
                /* unescape double quotation '\"'->'"' */
                for (i = j = str; *i != '"'; i++, j++) {
                        if (*i == '\0')
                                return -EINVAL;
                        if (i[0] == '\\' && i[1] == '"')
                                i++;
                        *j = *i;
                }
                j[0] = '\0';
        } else {
                _cleanup_free_ char *unescaped = NULL;
                ssize_t l;

                /* find the end position of value */
                for (i = str; *i != '"'; i++) {
                        if (i[0] == '\\')
                                i++;
                        if (*i == '\0')
                                return -EINVAL;
                }
                i[0] = '\0';

                l = cunescape_length(str, i - str, 0, &unescaped);
                if (l < 0)
                        return l;

                assert(l <= i - str);
                memcpy(str, unescaped, l + 1);
        }

        *ret_value = str;
        *ret_endpos = i + 1;
        return 0;
}

size_t udev_replace_whitespace(const char *str, char *to, size_t len) {
        bool is_space = false;
        size_t i, j;

        assert(str);
        assert(to);

        /* Copy from 'str' to 'to', while removing all leading and trailing whitespace, and replacing
         * each run of consecutive whitespace with a single underscore. The chars from 'str' are copied
         * up to the \0 at the end of the string, or at most 'len' chars.  This appends \0 to 'to', at
         * the end of the copied characters.
         *
         * If 'len' chars are copied into 'to', the final \0 is placed at len+1 (i.e. 'to[len] = \0'),
         * so the 'to' buffer must have at least len+1 chars available.
         *
         * Note this may be called with 'str' == 'to', i.e. to replace whitespace in-place in a buffer.
         * This function can handle that situation.
         *
         * Note that only 'len' characters are read from 'str'. */

        i = strspn(str, WHITESPACE);

        for (j = 0; j < len && i < len && str[i] != '\0'; i++) {
                if (isspace(str[i])) {
                        is_space = true;
                        continue;
                }

                if (is_space) {
                        if (j + 1 >= len)
                                break;

                        to[j++] = '_';
                        is_space = false;
                }
                to[j++] = str[i];
        }

        to[j] = '\0';
        return j;
}

size_t udev_replace_ifname(char *str) {
        size_t replaced = 0;

        assert(str);

        /* See ifname_valid_full(). */

        for (char *p = str; *p != '\0'; p++)
                if (!ifname_valid_char(*p)) {
                        *p = '_';
                        replaced++;
                }

        return replaced;
}

size_t udev_replace_chars(char *str, const char *allow) {
        size_t i = 0, replaced = 0;

        assert(str);

        /* allow chars in allow list, plain ascii, hex-escaping and valid utf8. */

        while (str[i] != '\0') {
                int len;

                if (allow_listed_char_for_devnode(str[i], allow)) {
                        i++;
                        continue;
                }

                /* accept hex encoding */
                if (str[i] == '\\' && str[i+1] == 'x') {
                        i += 2;
                        continue;
                }

                /* accept valid utf8 */
                len = utf8_encoded_valid_unichar(str + i, SIZE_MAX);
                if (len > 1) {
                        i += len;
                        continue;
                }

                /* if space is allowed, replace whitespace with ordinary space */
                if (isspace(str[i]) && allow && strchr(allow, ' ')) {
                        str[i] = ' ';
                        i++;
                        replaced++;
                        continue;
                }

                /* everything else is replaced with '_' */
                str[i] = '_';
                i++;
                replaced++;
        }
        return replaced;
}

int udev_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *temp = NULL;
        char *subsys, *sysname, *attr;
        const char *val;
        int r;

        assert(string);
        assert(result);

        /* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */

        if (string[0] != '[')
                return -EINVAL;

        temp = strdup(string);
        if (!temp)
                return -ENOMEM;

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (!sysname)
                return -EINVAL;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (!attr)
                return -EINVAL;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] == '\0')
                attr = NULL;

        if (read_value && !attr)
                return -EINVAL;

        r = sd_device_new_from_subsystem_sysname(&dev, subsys, sysname);
        if (r < 0)
                return r;

        if (read_value) {
                r = sd_device_get_sysattr_value(dev, attr, &val);
                if (r < 0 && !ERRNO_IS_PRIVILEGE(r) && r != -ENOENT)
                        return r;
                if (r >= 0)
                        strscpy(result, maxsize, val);
                else
                        result[0] = '\0';
                log_debug("value '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        } else {
                r = sd_device_get_syspath(dev, &val);
                if (r < 0)
                        return r;

                strscpyl(result, maxsize, val, attr ? "/" : NULL, attr ?: NULL, NULL);
                log_debug("path '[%s/%s]%s' is '%s'", subsys, sysname, strempty(attr), result);
        }
        return 0;
}

bool devpath_conflict(const char *a, const char *b) {
        /* This returns true when two paths are equivalent, or one is a child of another. */

        if (!a || !b)
                return false;

        for (; *a != '\0' && *b != '\0'; a++, b++)
                if (*a != *b)
                        return false;

        return *a == '/' || *b == '/' || *a == *b;
}

int udev_queue_is_empty(void) {
        return access("/run/udev/queue", F_OK) < 0 ?
                (errno == ENOENT ? true : -errno) : false;
}

int udev_queue_init(void) {
        _cleanup_close_ int fd = -1;

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (inotify_add_watch(fd, "/run/udev" , IN_DELETE) < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int device_is_power_sink(sd_device *device) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool found_source = false, found_sink = false;
        sd_device *parent, *d;
        int r;

        assert(device);

        /* USB-C power supply device has two power roles: source or sink. See,
         * https://docs.kernel.org/admin-guide/abi-testing.html#abi-file-testing-sysfs-class-typec */

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "typec", true);
        if (r < 0)
                return r;

        r = sd_device_get_parent(device, &parent);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, parent);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                const char *val;

                r = sd_device_get_sysattr_value(d, "power_role", &val);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_device_debug_errno(d, r, "Failed to read 'power_role' sysfs attribute, ignoring: %m");
                        continue;
                }

                if (strstr(val, "[source]")) {
                        found_source = true;
                        log_device_debug(d, "The USB type-C port is in power source mode.");
                } else if (strstr(val, "[sink]")) {
                        found_sink = true;
                        log_device_debug(d, "The USB type-C port is in power sink mode.");
                }
        }

        if (found_sink)
                log_device_debug(device, "The USB type-C device has at least one port in power sink mode.");
        else if (!found_source)
                log_device_debug(device, "The USB type-C device has no port in power source mode, assuming the device is in power sink mode.");
        else
                log_device_debug(device, "All USB type-C ports are in power source mode.");

        return found_sink || !found_source;
}

static bool battery_is_discharging(sd_device *d) {
        const char *val;
        int r;

        assert(d);

        r = sd_device_get_sysattr_value(d, "scope", &val);
        if (r < 0) {
                if (r != -ENOENT)
                        log_device_debug_errno(d, r, "Failed to read 'scope' sysfs attribute, ignoring: %m");
        } else if (streq(val, "Device")) {
                log_device_debug(d, "The power supply is a device battery, ignoring device.");
                return false;
        }

        r = device_get_sysattr_bool(d, "present");
        if (r < 0)
                log_device_debug_errno(d, r, "Failed to read 'present' sysfs attribute, assuming the battery is present: %m");
        else if (r == 0) {
                log_device_debug(d, "The battery is not present, ignoring the power supply.");
                return false;
        }

        /* Possible values: "Unknown", "Charging", "Discharging", "Not charging", "Full" */
        r = sd_device_get_sysattr_value(d, "status", &val);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to read 'status' sysfs attribute, assuming the battery is discharging: %m");
                return true;
        }
        if (!streq(val, "Discharging")) {
                log_device_debug(d, "The battery status is '%s', assuming the battery is not used as a power source of this machine.", val);
                return false;
        }

        return true;
}

int on_ac_power(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool found_ac_online = false, found_discharging_battery = false;
        sd_device *d;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "power_supply", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                /* See
                 * https://github.com/torvalds/linux/blob/4eef766b7d4d88f0b984781bc1bcb574a6eafdc7/include/linux/power_supply.h#L176
                 * for defined power source types. Also see:
                 * https://docs.kernel.org/admin-guide/abi-testing.html#abi-file-testing-sysfs-class-power */

                const char *val;
                r = sd_device_get_sysattr_value(d, "type", &val);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to read 'type' sysfs attribute, ignoring device: %m");
                        continue;
                }

                /* Ignore USB-C power supply in source mode. See issue #21988. */
                if (streq(val, "USB")) {
                        r = device_is_power_sink(d);
                        if (r <= 0) {
                                if (r < 0)
                                        log_device_debug_errno(d, r, "Failed to determine the current power role, ignoring device: %m");
                                else
                                        log_device_debug(d, "USB power supply is in source mode, ignoring device.");
                                continue;
                        }
                }

                if (streq(val, "Battery")) {
                        if (battery_is_discharging(d)) {
                                found_discharging_battery = true;
                                log_device_debug(d, "The power supply is a battery and currently discharging.");
                        }
                        continue;
                }

                r = device_get_sysattr_unsigned(d, "online", NULL);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to query 'online' sysfs attribute, ignoring device: %m");
                        continue;
                } else if (r > 0)  /* At least 1 and 2 are defined as different types of 'online' */
                        found_ac_online = true;

                log_device_debug(d, "The power supply is currently %s.", r > 0 ? "online" : "offline");
        }

        if (found_ac_online) {
                log_debug("Found at least one online non-battery power supply, system is running on AC.");
                return true;
        } else if (found_discharging_battery) {
                log_debug("Found at least one discharging battery and no online power sources, assuming system is running from battery.");
                return false;
        } else {
                log_debug("No power supply reported online and no discharging battery found, assuming system is running on AC.");
                return true;
        }
}

bool udev_available(void) {
        static int cache = -1;

        /* The service systemd-udevd is started only when /sys is read write.
         * See systemd-udevd.service: ConditionPathIsReadWrite=/sys
         * Also, our container interface (http://systemd.io/CONTAINER_INTERFACE/) states that /sys must
         * be mounted in read-only mode in containers. */

        if (cache >= 0)
                return cache;

        return (cache = (path_is_read_only_fs("/sys/") <= 0));
}
