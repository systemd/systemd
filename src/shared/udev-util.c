/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "device-private.h"
#include "device-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "id128-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "udev-util.h"
#include "utf8.h"

int udev_set_max_log_level(char *str) {
        size_t n;

        /* This may modify input string. */

        if (isempty(str))
                return 0;

        /* unquote */
        n = strlen(str);
        if (n >= 2 &&
            ((str[0] == '"' && str[n - 1] == '"') ||
             (str[0] == '\'' && str[n - 1] == '\''))) {
                str[n - 1] = '\0';
                str++;
        }

        /* we set the udev log level here explicitly, this is supposed
         * to regulate the code in libudev/ and udev/. */
        return log_set_max_level_from_string(str);
}

int udev_parse_config(void) {
        _cleanup_free_ char *log_val = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/udev/udev.conf",
                           "udev_log", &log_val);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        r = udev_set_max_log_level(log_val);
        if (r < 0)
                log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                           "Failed to set udev log level '%s', ignoring: %m", log_val);

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

                FOREACH_DEVICE_DEVLINK(device, link)
                        if (path_equal(link, data->devlink))
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

int device_is_processing(sd_device *dev) {
        int r;

        assert(dev);

        r = sd_device_get_property_value(dev, "ID_PROCESSING", NULL);
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

int udev_queue_is_empty(void) {
        return access("/run/udev/queue", F_OK) < 0 ?
                (errno == ENOENT ? true : -errno) : false;
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

int device_get_vendor_string(sd_device *device, const char **ret) {
        int r;

        assert(device);

        FOREACH_STRING(field, "ID_VENDOR_FROM_DATABASE", "ID_VENDOR") {
                r = sd_device_get_property_value(device, field, ret);
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

int device_get_model_string(sd_device *device, const char **ret) {
        int r;

        assert(device);

        FOREACH_STRING(field, "ID_MODEL_FROM_DATABASE", "ID_MODEL") {
                r = sd_device_get_property_value(device, field, ret);
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

int device_get_property_value_with_fallback(
                sd_device *device,
                const char *prop,
                Hashmap *extra_props,
                const char **ret) {
        const char *value;
        int r;

        assert(device);
        assert(prop);
        assert(ret);

        r = sd_device_get_property_value(device, prop, &value);
        if (r < 0) {
                if (r != -ENOENT)
                        return r;

                value = hashmap_get(extra_props, prop);
                if (!value)
                        return -ENOENT;
        }

        *ret = value;

        return 1;
}
