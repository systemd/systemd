/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "proc-cmdline.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-set-default.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        char **ret = data;

        if (streq(key, "systemd.unit")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;
                if (!unit_name_is_valid(value, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                        log_warning("Unit name specified on %s= is not valid, ignoring: %s", key, value);
                        return 0;
                }

                return free_and_strdup_warn(ret, key);

        } else if (!value) {
                if (runlevel_to_target(key))
                        return free_and_strdup_warn(ret, key);
        }

        return 0;
}

static void emit_cmdline_warning(void) {
        if (arg_quiet || arg_root)
                /* don't bother checking the commandline if we're operating on a container */
                return;

        _cleanup_free_ char *override = NULL;
        int r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, &override, 0);
        if (r < 0)
                log_debug_errno(r, "Failed to parse kernel command line, ignoring: %m");
        if (override)
                log_notice("Note: found \"%s\" on the kernel commandline, which overrides the default unit.",
                           override);
}

static int determine_default(char **ret_name) {
        int r;

        if (install_client_side()) {
                r = unit_file_get_default(arg_scope, arg_root, ret_name);
                if (r == -ERFKILL)
                        return log_error_errno(r, "Failed to get default target: Unit file is masked.");
                if (r < 0)
                        return log_error_errno(r, "Failed to get default target: %m");
                return 0;

        } else {
                sd_bus *bus;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *name;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                r = bus_call_method(bus, bus_systemd_mgr, "GetDefaultTarget", &error, &reply, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to get default target: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "s", &name);
                if (r < 0)
                        return bus_log_parse_error(r);

                return free_and_strdup_warn(ret_name, name);
        }
}

int verb_get_default(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *name = NULL;
        int r;

        r = determine_default(&name);
        if (r < 0)
                return r;

        printf("%s\n", name);

        emit_cmdline_warning();

        return 0;
}

int verb_set_default(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *unit = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        int r;

        assert(argc >= 2);
        assert(argv);

        r = unit_name_mangle_with_suffix(argv[1], "set-default",
                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                         ".target", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        if (install_client_side()) {
                r = unit_file_set_default(arg_scope, UNIT_FILE_FORCE, arg_root, unit, &changes, &n_changes);
                install_changes_dump(r, "set default", changes, n_changes, arg_quiet);
                if (r < 0)
                        goto finish;
        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                sd_bus *bus;

                polkit_agent_open_maybe();

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                r = bus_call_method(bus, bus_systemd_mgr, "SetDefaultTarget", &error, &reply, "sb", unit, 1);
                if (r < 0)
                        return log_error_errno(r, "Failed to set default target: %s", bus_error_message(&error, r));

                r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet, &changes, &n_changes);
                if (r < 0)
                        goto finish;

                /* Try to reload if enabled */
                if (!arg_no_reload) {
                        r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
                        if (r < 0)
                                goto finish;
                }
        }

        emit_cmdline_warning();

        if (!arg_quiet) {
                _cleanup_free_ char *final = NULL;

                r = determine_default(&final);
                if (r < 0)
                        goto finish;

                if (!streq(final, unit))
                        log_notice("Note: \"%s\" is the default unit (possibly a runtime override).", final);
        }

finish:
        install_changes_free(changes, n_changes);

        return r < 0 ? r : 0;
}
