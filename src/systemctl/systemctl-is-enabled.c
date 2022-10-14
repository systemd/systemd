/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-is-enabled.h"
#include "systemctl-sysv-compat.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int show_installation_targets_client_side(const char *name) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileFlags flags;
        char **p;
        int r;

        p = STRV_MAKE(name);
        flags = UNIT_FILE_DRY_RUN |
                (arg_runtime ? UNIT_FILE_RUNTIME : 0);

        r = unit_file_disable(LOOKUP_SCOPE_SYSTEM, flags, NULL, p, &changes, &n_changes);
        if (r < 0)
                return log_error_errno(r, "Failed to get file links for %s: %m", name);

        for (size_t i = 0; i < n_changes; i++)
                if (changes[i].type == INSTALL_CHANGE_UNLINK)
                        printf("  %s\n", changes[i].path);

        return 0;
}

static int show_installation_targets(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *link;
        int r;

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitFileLinks", &error, &reply, "sb", name, arg_runtime);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit file links for %s: %s", name, bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "s", &link)) > 0)
                printf("  %s\n", link);

        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

int verb_is_enabled(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        bool enabled;
        int r;

        r = mangle_names("to check", strv_skip(argv, 1), &names);
        if (r < 0)
                return r;

        r = enable_sysv_units(argv[0], names);
        if (r < 0)
                return r;

        enabled = r > 0;

        if (install_client_side()) {
                STRV_FOREACH(name, names) {
                        UnitFileState state;

                        r = unit_file_get_state(arg_scope, arg_root, *name, &state);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get unit file state for %s: %m", *name);

                        if (IN_SET(state,
                                   UNIT_FILE_ENABLED,
                                   UNIT_FILE_ENABLED_RUNTIME,
                                   UNIT_FILE_STATIC,
                                   UNIT_FILE_ALIAS,
                                   UNIT_FILE_INDIRECT,
                                   UNIT_FILE_GENERATED))
                                enabled = true;

                        if (!arg_quiet) {
                                puts(unit_file_state_to_string(state));
                                if (arg_full) {
                                        r = show_installation_targets_client_side(*name);
                                        if (r < 0)
                                                return r;
                                }
                        }
                }

                r = 0;
        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                sd_bus *bus;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                STRV_FOREACH(name, names) {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                        const char *s;

                        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitFileState", &error, &reply, "s", *name);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get unit file state for %s: %s", *name, bus_error_message(&error, r));

                        r = sd_bus_message_read(reply, "s", &s);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (STR_IN_SET(s, "enabled", "enabled-runtime", "static", "alias", "indirect", "generated"))
                                enabled = true;

                        if (!arg_quiet) {
                                puts(s);
                                if (arg_full) {
                                        r = show_installation_targets(bus, *name);
                                        if (r < 0)
                                                return r;
                                }
                        }
                }
        }

        return enabled ? EXIT_SUCCESS : EXIT_FAILURE;
}
