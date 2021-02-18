/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "device-private.h"
#include "path-util.h"
#include "udevadm-util.h"
#include "unit-name.h"

static int find_device_from_path(const char *path, sd_device **ret) {
        if (path_startswith(path, "/sys/"))
                return sd_device_new_from_syspath(ret, path);

        if (path_startswith(path, "/dev/")) {
                struct stat st;

                if (stat(path, &st) < 0)
                        return -errno;

                return sd_device_new_from_stat_rdev(ret, &st);
        }

        return -EINVAL;
}

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

                return find_device_from_path(path, ret);
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
        _cleanup_free_ char *path = NULL;
        int r;

        assert(id);
        assert(ret);

        if (prefix) {
                if (!path_startswith(id, prefix)) {
                        id = path = path_join(prefix, id);
                        if (!path)
                                return -ENOMEM;
                }
        } else {
                /* In cases where the argument is generic (no prefix specified),
                 * check if the argument looks like a device unit name. */
                r = find_device_from_unit(id, ret);
                if (r >= 0)
                        return r;
        }

        return find_device_from_path(id, ret);
}
