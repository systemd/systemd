/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "parse-util.h"
#include "strv.h"
#include "systemctl-needs-restart.h"
#include "systemctl-show.h"
#include "systemctl-util.h"

int set_needs_restart(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char **patterns = NULL;
        char **name;
        int r, one = 1, ret = 0;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *path = NULL, *unit = NULL;
                uint32_t id;

                if (safe_atou32(*name, &id) < 0) {
                        if (strv_push(&patterns, *name) < 0)
                                return log_oom();

                        continue;
                } else {
                        /* Interpret as PID */
                        r = get_unit_dbus_path_by_pid(bus, id, &path);
                        if (r < 0) {
                                ret = r;
                                continue;
                        }

                        r = unit_name_from_dbus_path(path, &unit);
                        if (r < 0)
                                return log_oom();
                }

                r = sd_bus_set_property(bus,
                                        "org.freedesktop.systemd1",
                                        path,
                                        "org.freedesktop.systemd1.Unit",
                                        "NeedsRestart",
                                        &error,
                                        "b", &one);
                if (r >= 0)
                        continue;

                ret = log_error_errno(r, "Failed to set NeedsRestart property of %s: %s",
                                      unit, bus_error_message(&error, r));
        }

        if (!strv_isempty(patterns)) {
                _cleanup_strv_free_ char **names = NULL;

                r = expand_unit_names(bus, patterns, NULL, &names, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to expand names: %m");

                r = maybe_extend_with_unit_dependencies(bus, &names);
                if (r < 0)
                        return r;

                STRV_FOREACH(name, names) {
                        _cleanup_free_ char *path = NULL;

                        path = unit_dbus_path_from_name(*name);
                        if (!path)
                                return log_oom();

                        r = sd_bus_set_property(bus,
                                                "org.freedesktop.systemd1",
                                                path,
                                                "org.freedesktop.systemd1.Unit",
                                                "NeedsRestart",
                                                &error,
                                                "b", &one);
                        if (r < 0)
                                ret = log_error_errno(r, "Failed to set NeedsRestart property of %s: %s",
                                                      *name, bus_error_message(&error, r));
                }
        }

        return ret;
}
