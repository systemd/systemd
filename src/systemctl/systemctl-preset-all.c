/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-preset-all.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_preset_all(int argc, char *argv[], void *userdata) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        int r;

        if (install_client_side()) {
                r = unit_file_preset_all(arg_runtime_scope, unit_file_flags_from_args(), arg_root, arg_preset_mode, &changes, &n_changes);
                install_changes_dump(r, "preset", changes, n_changes, arg_quiet);

                if (r > 0)
                        r = 0;
        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                sd_bus *bus;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                polkit_agent_open_maybe();

                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "PresetAllUnitFiles",
                                &error,
                                &reply,
                                "sbb",
                                unit_file_preset_mode_to_string(arg_preset_mode),
                                arg_runtime,
                                arg_force);
                if (r < 0)
                        return log_error_errno(r, "Failed to preset all units: %s", bus_error_message(&error, r));

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
