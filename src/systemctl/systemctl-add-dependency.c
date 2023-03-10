/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-add-dependency.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_add_dependency(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        _cleanup_free_ char *target = NULL;
        const char *verb = argv[0];
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitDependency dep;
        int r;

        if (!argv[1])
                return 0;

        r = unit_name_mangle_with_suffix(argv[1], "as target",
                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                         ".target", &target);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        r = mangle_names("as dependency", strv_skip(argv, 2), &names);
        if (r < 0)
                return r;

        if (streq(verb, "add-wants"))
                dep = UNIT_WANTS;
        else if (streq(verb, "add-requires"))
                dep = UNIT_REQUIRES;
        else
                assert_not_reached();

        if (install_client_side()) {
                r = unit_file_add_dependency(arg_runtime_scope, unit_file_flags_from_args(), arg_root, names, target, dep, &changes, &n_changes);
                install_changes_dump(r, "add dependency on", changes, n_changes, arg_quiet);

                if (r > 0)
                        r = 0;
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                sd_bus *bus;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                polkit_agent_open_maybe();

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "AddDependencyUnitFiles");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, names);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "ssbb", target, unit_dependency_to_string(dep), arg_runtime, arg_force);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, &reply);
                if (r < 0)
                        return log_error_errno(r, "Failed to add dependency: %s", bus_error_message(&error, r));

                r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet, &changes, &n_changes);
                if (r < 0)
                        goto finish;

                if (arg_no_reload) {
                        r = 0;
                        goto finish;
                }

                r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
                if (r > 0)
                        r = 0;
        }

finish:
        install_changes_free(changes, n_changes);

        return r;
}
