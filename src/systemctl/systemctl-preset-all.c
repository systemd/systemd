/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "install.h"
#include "log.h"
#include "systemctl.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-preset-all.h"
#include "systemctl-util.h"
#include "verbs.h"

int verb_preset_all(int argc, char *argv[], void *userdata) {
        int r;

        if (should_bypass("SYSTEMD_PRESET"))
                return 0;

        if (install_client_side() != INSTALL_CLIENT_SIDE_NO) {
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                r = unit_file_preset_all(arg_runtime_scope, unit_file_flags_from_args(), arg_root, arg_preset_mode, &changes, &n_changes);
                /* We do not propagate failure for individual units here. */
                (void) install_changes_dump(r, "preset all", changes, n_changes, arg_quiet);
                if (r < 0)
                        return r;
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

                r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet);
                if (r < 0)
                        return r;

                if (!arg_no_reload) {
                        r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
