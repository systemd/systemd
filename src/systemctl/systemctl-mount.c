/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-mount.h"
#include "systemctl-util.h"
#include "systemctl.h"

int mount_bind(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *n = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = unit_name_mangle(argv[1], arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "BindMountUnit",
                        &error,
                        NULL,
                        "sssbb",
                        n,
                        argv[2],
                        argv[3],
                        arg_read_only,
                        arg_mkdir);
        if (r < 0)
                return log_error_errno(r, "Failed to bind mount: %s", bus_error_message(&error, r));

        return 0;
}

int mount_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *n = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = unit_name_mangle(argv[1], arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        r = bus_message_new_method_call(
                        bus,
                        &m,
                        bus_systemd_mgr,
                        "MountImageUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssbb",
                        n,
                        argv[2],
                        argc > 3 ? argv[3] : "",
                        arg_read_only,
                        arg_mkdir);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        if (argc == 5) {
                r = sd_bus_message_append(m, "(ss)", "root", argv[4]);
                if (r < 0)
                        return bus_log_create_error(r);
        } else if (argc > 5 && argc % 2 != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid number of mount options.");
        else if (argc > 5) {
                char **partition, **mount_options;

                STRV_FOREACH_PAIR(partition, mount_options, strv_skip(argv, 4)) {
                        r = sd_bus_message_append(m, "(ss)", *partition, *mount_options);
                        if (r < 0)
                                return bus_log_create_error(r);
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, -1, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to mount image: %s", bus_error_message(&error, r));

        return 0;
}
