/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "device-util.h"
#include "env-file.h"
#include "log.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"

static const char* const resolve_name_timing_table[_RESOLVE_NAME_TIMING_MAX] = {
        [RESOLVE_NAME_NEVER] = "never",
        [RESOLVE_NAME_LATE] = "late",
        [RESOLVE_NAME_EARLY] = "early",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_name_timing, ResolveNameTiming);

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec,
                ResolveNameTiming *ret_resolve_name_timing) {

        _cleanup_free_ char *log_val = NULL, *children_max = NULL, *exec_delay = NULL, *event_timeout = NULL, *resolve_names = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/udev/udev.conf",
                           "udev_log", &log_val,
                           "children_max", &children_max,
                           "exec_delay", &exec_delay,
                           "event_timeout", &event_timeout,
                           "resolve_names", &resolve_names);
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
                r = log_set_max_level_from_string_realm(LOG_REALM_UDEV, log);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set udev log level '%s', ignoring: %m", log);
        }

        if (ret_children_max && children_max) {
                r = safe_atou(children_max, ret_children_max);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set parse children_max=%s, ignoring: %m", children_max);
        }

        if (ret_exec_delay_usec && exec_delay) {
                r = parse_sec(exec_delay, ret_exec_delay_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set parse exec_delay=%s, ignoring: %m", exec_delay);
        }

        if (ret_event_timeout_usec && event_timeout) {
                r = parse_sec(event_timeout, ret_event_timeout_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set parse event_timeout=%s, ignoring: %m", event_timeout);
        }

        if (ret_resolve_name_timing && resolve_names) {
                ResolveNameTiming t;

                t = resolve_name_timing_from_string(resolve_names);
                if (t < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "failed to set parse resolve_names=%s, ignoring.", resolve_names);
                else
                        *ret_resolve_name_timing = t;
        }

        return 0;
}

struct DeviceMonitorData {
        const char *sysname;
        sd_device *device;
};

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        struct DeviceMonitorData *data = userdata;
        const char *sysname;

        assert(device);
        assert(data);
        assert(data->sysname);
        assert(!data->device);

        if (sd_device_get_sysname(device, &sysname) >= 0 && streq(sysname, data->sysname)) {
                data->device = sd_device_ref(device);
                return sd_event_exit(sd_device_monitor_get_event(monitor), 0);
        }

        return 0;
}

static int device_timeout_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        return sd_event_exit(sd_event_source_get_event(s), -ETIMEDOUT);
}

int device_wait_for_initialization(sd_device *device, const char *subsystem, usec_t timeout, sd_device **ret) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *timeout_source = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        struct DeviceMonitorData data = {};
        int r;

        assert(device);

        if (sd_device_get_is_initialized(device) > 0) {
                if (ret)
                        *ret = sd_device_ref(device);
                return 0;
        }

        assert_se(sd_device_get_sysname(device, &data.sysname) >= 0);

        /* Wait until the device is initialized, so that we can get access to the ID_PATH property */

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event: %m");

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire monitor: %m");

        if (!subsystem) {
                r = sd_device_get_subsystem(device, &subsystem);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(device, r, "Failed to get subsystem: %m");
        }

        if (subsystem) {
                r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add %s subsystem match to monitor: %m", subsystem);
        }

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(monitor, device_monitor_handler, &data);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        if (timeout != USEC_INFINITY) {
                r = sd_event_add_time(event, &timeout_source,
                                      CLOCK_MONOTONIC, now(CLOCK_MONOTONIC) + timeout, 0,
                                      device_timeout_handler, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add timeout event source: %m");
        }

        /* Check again, maybe things changed. Udev will re-read the db if the device wasn't initialized
         * yet. */
        if (sd_device_get_is_initialized(device) > 0) {
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

int device_is_renaming(sd_device *dev) {
        int r;

        assert(dev);

        r = sd_device_get_property_value(dev, "ID_RENAMING", NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        return r >= 0;
}

bool device_for_action(sd_device *dev, DeviceAction action) {
        DeviceAction a;

        assert(dev);

        if (device_get_action(dev, &a) < 0)
                return false;

        return a == action;
}
