/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "locale-util.h"
#include "path-util.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-enable.h"
#include "systemctl-start-unit.h"
#include "systemctl-sysv-compat.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int normalize_filenames(char **names) {
        char **u;
        int r;

        STRV_FOREACH(u, names)
                if (!path_is_absolute(*u)) {
                        char* normalized_path;

                        if (!isempty(arg_root))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Non-absolute paths are not allowed when --root is used: %s",
                                                       *u);

                        if (!strchr(*u,'/'))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Link argument does contain at least one directory separator: %s",
                                                       *u);

                        r = path_make_absolute_cwd(*u, &normalized_path);
                        if (r < 0)
                                return r;

                        free_and_replace(*u, normalized_path);
                }

        return 0;
}

static int normalize_names(char **names, bool warn_if_path) {
        char **u;
        bool was_path = false;

        STRV_FOREACH(u, names) {
                int r;

                if (!is_path(*u))
                        continue;

                r = free_and_strdup(u, basename(*u));
                if (r < 0)
                        return log_error_errno(r, "Failed to normalize unit file path: %m");

                was_path = true;
        }

        if (warn_if_path && was_path)
                log_warning("Warning: Can't execute disable on the unit file path. Proceeding with the unit name.");

        return 0;
}

int enable_unit(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        const char *verb = argv[0];
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        int carries_install_info = -1;
        bool ignore_carries_install_info = arg_quiet;
        int r;

        if (!argv[1])
                return 0;

        r = mangle_names("to enable", strv_skip(argv, 1), &names);
        if (r < 0)
                return r;

        r = enable_sysv_units(verb, names);
        if (r < 0)
                return r;

        /* If the operation was fully executed by the SysV compat, let's finish early */
        if (strv_isempty(names)) {
                if (arg_no_reload || install_client_side())
                        return 0;
                return daemon_reload(argc, argv, userdata);
        }

        if (streq(verb, "disable")) {
                r = normalize_names(names, true);
                if (r < 0)
                        return r;
        }

        if (streq(verb, "link")) {
                r = normalize_filenames(names);
                if (r < 0)
                        return r;
        }

        if (install_client_side()) {
                UnitFileFlags flags;

                flags = unit_file_flags_from_args();
                if (streq(verb, "enable")) {
                        r = unit_file_enable(arg_scope, flags, arg_root, names, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "disable"))
                        r = unit_file_disable(arg_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "reenable")) {
                        r = unit_file_reenable(arg_scope, flags, arg_root, names, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "link"))
                        r = unit_file_link(arg_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "preset")) {
                        r = unit_file_preset(arg_scope, flags, arg_root, names, arg_preset_mode, &changes, &n_changes);
                } else if (streq(verb, "mask"))
                        r = unit_file_mask(arg_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "unmask"))
                        r = unit_file_unmask(arg_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "revert"))
                        r = unit_file_revert(arg_scope, arg_root, names, &changes, &n_changes);
                else
                        assert_not_reached("Unknown verb");

                unit_file_dump_changes(r, verb, changes, n_changes, arg_quiet);
                if (r < 0)
                        goto finish;
                r = 0;
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                bool expect_carries_install_info = false;
                bool send_runtime = true, send_force = true, send_preset_mode = false;
                const char *method;
                sd_bus *bus;

                if (STR_IN_SET(verb, "mask", "unmask")) {
                        char **name;
                        _cleanup_(lookup_paths_free) LookupPaths lp = {};

                        r = lookup_paths_init(&lp, arg_scope, 0, arg_root);
                        if (r < 0)
                                return r;

                        STRV_FOREACH(name, names) {
                                r = unit_exists(&lp, *name);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        log_notice("Unit %s does not exist, proceeding anyway.", *name);
                        }
                }

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                polkit_agent_open_maybe();

                if (streq(verb, "enable")) {
                        method = "EnableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "disable")) {
                        method = "DisableUnitFiles";
                        send_force = false;
                } else if (streq(verb, "reenable")) {
                        method = "ReenableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "link"))
                        method = "LinkUnitFiles";
                else if (streq(verb, "preset")) {

                        if (arg_preset_mode != UNIT_FILE_PRESET_FULL) {
                                method = "PresetUnitFilesWithMode";
                                send_preset_mode = true;
                        } else
                                method = "PresetUnitFiles";

                        expect_carries_install_info = true;
                        ignore_carries_install_info = true;
                } else if (streq(verb, "mask"))
                        method = "MaskUnitFiles";
                else if (streq(verb, "unmask")) {
                        method = "UnmaskUnitFiles";
                        send_force = false;
                } else if (streq(verb, "revert")) {
                        method = "RevertUnitFiles";
                        send_runtime = send_force = false;
                } else
                        assert_not_reached("Unknown verb");

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, names);
                if (r < 0)
                        return bus_log_create_error(r);

                if (send_preset_mode) {
                        r = sd_bus_message_append(m, "s", unit_file_preset_mode_to_string(arg_preset_mode));
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                if (send_runtime) {
                        r = sd_bus_message_append(m, "b", arg_runtime);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                if (send_force) {
                        r = sd_bus_message_append(m, "b", arg_force);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_call(bus, m, 0, &error, &reply);
                if (r < 0)
                        return log_error_errno(r, "Failed to %s unit: %s", verb, bus_error_message(&error, r));

                if (expect_carries_install_info) {
                        r = sd_bus_message_read(reply, "b", &carries_install_info);
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

                r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet, &changes, &n_changes);
                if (r < 0)
                        goto finish;

                /* Try to reload if enabled */
                if (!arg_no_reload)
                        r = daemon_reload(argc, argv, userdata);
                else
                        r = 0;
        }

        if (carries_install_info == 0 && !ignore_carries_install_info)
                log_notice("The unit files have no installation config (WantedBy=, RequiredBy=, Also=,\n"
                           "Alias= settings in the [Install] section, and DefaultInstance= for template\n"
                           "units). This means they are not meant to be enabled using systemctl.\n"
                           " \n" /* trick: the space is needed so that the line does not get stripped from output */
                           "Possible reasons for having this kind of units are:\n"
                           "%1$s A unit may be statically enabled by being symlinked from another unit's\n"
                           "  .wants/ or .requires/ directory.\n"
                           "%1$s A unit's purpose may be to act as a helper for some other unit which has\n"
                           "  a requirement dependency on it.\n"
                           "%1$s A unit may be started when needed via activation (socket, path, timer,\n"
                           "  D-Bus, udev, scripted systemctl call, ...).\n"
                           "%1$s In case of template units, the unit is meant to be enabled with some\n"
                           "  instance name specified.",
                           special_glyph(SPECIAL_GLYPH_BULLET));

        if (arg_now && STR_IN_SET(argv[0], "enable", "disable", "mask")) {
                sd_bus *bus;
                size_t len, i;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        goto finish;

                len = strv_length(names);
                {
                        char *new_args[len + 2];

                        new_args[0] = (char*) (streq(argv[0], "enable") ? "start" : "stop");
                        for (i = 0; i < len; i++)
                                new_args[i + 1] = basename(names[i]);
                        new_args[i + 1] = NULL;

                        r = start_unit(len + 1, new_args, userdata);
                }
        }

finish:
        unit_file_changes_free(changes, n_changes);

        return r;
}
