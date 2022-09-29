/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "device-private.h"
#include "path-util.h"
#include "udevadm-util.h"
#include "unit-name.h"

static int find_device_from_unit(const char *unit_name, sd_device **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *unit_path = NULL, *syspath = NULL;
        int r;

        if (!unit_name_is_valid(unit_name, UNIT_NAME_PLAIN))
                return -EINVAL;

        if (unit_name_to_type(unit_name) != UNIT_DEVICE)
                return -EINVAL;

        r = bus_connect_system_systemd(&bus);
        if (r < 0) {
                _cleanup_free_ char *path = NULL;

                log_debug_errno(r, "Failed to open connection to systemd, using unit name as syspath: %m");

                r = unit_name_to_path(unit_name, &path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to convert \"%s\" to a device path: %m", unit_name);

                return sd_device_new_from_path(ret, path);
        }

        unit_path = unit_dbus_path_from_name(unit_name);
        if (!unit_path)
                return -ENOMEM;

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        unit_path,
                        "org.freedesktop.systemd1.Device",
                        "SysFSPath",
                        &error,
                        &syspath);
        if (r < 0)
                return log_debug_errno(r, "Failed to get SysFSPath= dbus property for %s: %s",
                                       unit_name, bus_error_message(&error, r));

        return sd_device_new_from_syspath(ret, syspath);
}

int find_device(const char *id, const char *prefix, sd_device **ret) {
        assert(id);
        assert(ret);

        if (sd_device_new_from_path(ret, id) >= 0)
                return 0;

        if (prefix && !path_startswith(id, prefix)) {
                _cleanup_free_ char *path = NULL;

                path = path_join(prefix, id);
                if (!path)
                        return -ENOMEM;

                if (sd_device_new_from_path(ret, path) >= 0)
                        return 0;
        }

        /* if a path is provided, then it cannot be a unit name. Let's return earlier. */
        if (is_path(id))
                return -ENODEV;

        /* Check if the argument looks like a device unit name. */
        return find_device_from_unit(id, ret);
}

int find_device_with_action(const char *id, sd_device_action_t action, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(id);
        assert(ret);
        assert(action >= 0 && action < _SD_DEVICE_ACTION_MAX);

        r = find_device(id, "/sys", &dev);
        if (r < 0)
                return r;

        r = device_read_uevent_file(dev);
        if (r < 0)
                return r;

        r = device_set_action(dev, action);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dev);
        return 0;
}

int parse_device_action(const char *str, sd_device_action_t *action) {
        sd_device_action_t a;

        assert(str);
        assert(action);

        if (streq(str, "help")) {
                dump_device_action_table();
                return 0;
        }

        a = device_action_from_string(str);
        if (a < 0)
                return a;

        *action = a;
        return 1;
}
