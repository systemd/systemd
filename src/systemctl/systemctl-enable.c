/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "path-util.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-enable.h"
#include "systemctl-start-unit.h"
#include "systemctl-sysv-compat.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int normalize_link_paths(char **paths) {
        int r;

        STRV_FOREACH(u, paths) {
                if (path_is_absolute(*u))
                        continue;

                if (!isempty(arg_root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Non-absolute paths are not allowed when --root= is used: %s",
                                               *u);

                if (!is_path(*u))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Link argument must contain at least one directory separator.\n"
                                               "If you intended to link a file in the current directory, try './%s' instead.",
                                               *u);

                char *normalized_path;

                r = path_make_absolute_cwd(*u, &normalized_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to normalize path '%s': %m", *u);

                path_simplify(normalized_path);

                free_and_replace(*u, normalized_path);
        }

        return 0;
}

static int normalize_names(char **names) {
        bool was_path = false;
        int r;

        STRV_FOREACH(u, names) {
                if (!is_path(*u))
                        continue;

                char *fn;

                r = path_extract_filename(*u, &fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", *u);

                free_and_replace(*u, fn);

                was_path = true;
        }

        if (was_path)
                log_warning("Warning: Can't execute disable on the unit file path. Proceeding with the unit name.");

        return 0;
}

int verb_enable(int argc, char *argv[], void *userdata) {
        const char *verb = ASSERT_PTR(argv[0]);
        _cleanup_strv_free_ char **names = NULL;
        int carries_install_info = -1;
        bool ignore_carries_install_info = arg_quiet || arg_no_warn;
        sd_bus *bus = NULL;
        int r;

        const char *operation = strjoina("to ", verb);
        r = mangle_names(operation, ASSERT_PTR(strv_skip(argv, 1)), &names);
        if (r < 0)
                return r;

        r = enable_sysv_units(verb, names);
        if (r < 0)
                return r;

        /* If the operation was fully executed by the SysV compat, let's finish early */
        if (strv_isempty(names)) {
                if (arg_no_reload || install_client_side())
                        return 0;

                r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
                return r > 0 ? 0 : r;
        }

        if (streq(verb, "disable"))
                r = normalize_names(names);
        else if (streq(verb, "link"))
                r = normalize_link_paths(names);
        else
                r = 0;
        if (r < 0)
                return r;

        if (install_client_side()) {
                UnitFileFlags flags;
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                flags = unit_file_flags_from_args();

                if (streq(verb, "enable")) {
                        r = unit_file_enable(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "disable")) {
                        r = unit_file_disable(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "reenable")) {
                        r = unit_file_reenable(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "link"))
                        r = unit_file_link(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "preset"))
                        r = unit_file_preset(arg_runtime_scope, flags, arg_root, names, arg_preset_mode, &changes, &n_changes);
                else if (streq(verb, "mask"))
                        r = unit_file_mask(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "unmask"))
                        r = unit_file_unmask(arg_runtime_scope, flags, arg_root, names, &changes, &n_changes);
                else if (streq(verb, "revert"))
                        r = unit_file_revert(arg_runtime_scope, arg_root, names, &changes, &n_changes);
                else
                        assert_not_reached();

                install_changes_dump(r, verb, changes, n_changes, arg_quiet);
                if (r < 0)
                        return r;
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                bool expect_carries_install_info = false;
                bool send_runtime = true, send_force = true, send_preset_mode = false;
                const char *method, *warn_trigger_operation = NULL;
                bool warn_trigger_ignore_masked = true; /* suppress "used uninitialized" warning */

                if (STR_IN_SET(verb, "mask", "unmask")) {
                        _cleanup_(lookup_paths_done) LookupPaths lp = {};

                        r = lookup_paths_init_or_warn(&lp, arg_runtime_scope, 0, arg_root);
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
                        method = "DisableUnitFilesWithFlagsAndInstallInfo";
                        expect_carries_install_info = true;
                        send_force = false;

                        warn_trigger_operation = "Disabling";
                        warn_trigger_ignore_masked = true;
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
                } else if (streq(verb, "mask")) {
                        method = "MaskUnitFiles";

                        warn_trigger_operation = "Masking";
                        warn_trigger_ignore_masked = false;
                } else if (streq(verb, "unmask")) {
                        method = "UnmaskUnitFiles";
                        send_force = false;
                } else if (streq(verb, "revert")) {
                        method = "RevertUnitFiles";
                        send_runtime = send_force = false;
                } else
                        assert_not_reached();

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
                        if (streq(method, "DisableUnitFilesWithFlagsAndInstallInfo"))
                                r = sd_bus_message_append(m, "t", arg_runtime ? (uint64_t) UNIT_FILE_RUNTIME : UINT64_C(0));
                        else
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

                r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet);
                if (r < 0)
                        return r;

                /* Try to reload if enabled */
                if (!arg_no_reload) {
                        r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
                        if (r < 0)
                                return r;
                }

                if (warn_trigger_operation && !arg_quiet && !arg_no_warn)
                        STRV_FOREACH(unit, names)
                                warn_triggering_units(bus, *unit, warn_trigger_operation, warn_trigger_ignore_masked);
        }

        if (carries_install_info == 0 && !ignore_carries_install_info)
                log_notice("The unit files have no installation config (WantedBy=, RequiredBy=, UpheldBy=,\n"
                           "Also=, or Alias= settings in the [Install] section, and DefaultInstance= for\n"
                           "template units). This means they are not meant to be enabled or disabled using systemctl.\n"
                           " \n" /* trick: the space is needed so that the line does not get stripped from output */
                           "Possible reasons for having these kinds of units are:\n"
                           "%1$s A unit may be statically enabled by being symlinked from another unit's\n"
                           "  .wants/, .requires/, or .upholds/ directory.\n"
                           "%1$s A unit's purpose may be to act as a helper for some other unit which has\n"
                           "  a requirement dependency on it.\n"
                           "%1$s A unit may be started when needed via activation (socket, path, timer,\n"
                           "  D-Bus, udev, scripted systemctl call, ...).\n"
                           "%1$s In case of template units, the unit is meant to be enabled with some\n"
                           "  instance name specified.",
                           special_glyph(SPECIAL_GLYPH_BULLET));

        if (streq(verb, "disable") && arg_runtime_scope == RUNTIME_SCOPE_USER && !arg_quiet && !arg_no_warn) {
                /* If some of the units are disabled in user scope but still enabled in global scope,
                 * we emit a warning for that. */

                /* No strv_free here, strings are owned by 'names' */
                _cleanup_free_ char **enabled_in_global_scope = NULL;

                STRV_FOREACH(name, names) {
                        UnitFileState state;

                        r = unit_file_get_state(RUNTIME_SCOPE_GLOBAL, arg_root, *name, &state);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0)
                                return log_error_errno(r, "Failed to get unit file state for %s: %m", *name);

                        if (IN_SET(state, UNIT_FILE_ENABLED, UNIT_FILE_ENABLED_RUNTIME)) {
                                r = strv_push(&enabled_in_global_scope, *name);
                                if (r < 0)
                                        return log_oom();
                        }
                }

                if (!strv_isempty(enabled_in_global_scope)) {
                        _cleanup_free_ char *joined = NULL;

                        joined = strv_join(enabled_in_global_scope, ", ");
                        if (!joined)
                                return log_oom();

                        log_notice("The following unit files have been enabled in global scope. This means\n"
                                   "they will still be started automatically after a successful disablement\n"
                                   "in user scope:\n"
                                   "%s",
                                   joined);
                }
        }

        if (arg_now) {
                _cleanup_strv_free_ char **new_args = NULL;
                const char *start_verb;
                bool accept_path, prohibit_templates;

                if (streq(verb, "enable")) {
                        start_verb = "start";
                        accept_path = true;
                        prohibit_templates = true;
                } else if (STR_IN_SET(verb, "disable", "mask")) {
                        start_verb = "stop";
                        accept_path = false;
                        prohibit_templates = false;
                } else if (streq(verb, "reenable")) {
                        /* Note that we use try-restart here. This matches the semantics of reenable better,
                         * and allows us to glob template units. */
                        start_verb = "try-restart";
                        accept_path = true;
                        prohibit_templates = false;
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--now can only be used with verb enable, disable, reenable, or mask.");

                if (install_client_side())
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE),
                                               "--now cannot be used when systemd is not running or in conjunction with --root=/--global, refusing.");

                assert(bus);

                if (strv_extend(&new_args, start_verb) < 0)
                        return log_oom();

                STRV_FOREACH(name, names) {
                        _cleanup_free_ char *fn = NULL;
                        const char *unit_name;

                        if (accept_path) {
                                /* 'enable' and 'reenable' accept path to unit files, so extract it first. */

                                r = path_extract_filename(*name, &fn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract filename of '%s': %m", *name);

                                unit_name = fn;
                        } else
                                unit_name = *name;

                        if (unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE)) {
                                char *globbed;

                                if (prohibit_templates) {
                                        /* Skip template units when enabling. Globbing doesn't make sense
                                         * since the semantics would be altered (we're operating on
                                         * DefaultInstance= when enabling), and starting template unit
                                         * is not supported anyway. */
                                        log_warning("Template unit is not supported by %s --now, skipping: %s",
                                                    verb, unit_name);
                                        continue;
                                }

                                assert(!STR_IN_SET(start_verb, "start", "restart"));

                                r = unit_name_replace_instance_full(unit_name, "*", /* accept_glob = */ true, &globbed);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to glob unit name '%s': %m", unit_name);

                                r = strv_consume(&new_args, globbed);
                        } else
                                r = strv_extend(&new_args, unit_name);
                        if (r < 0)
                                return log_oom();
                }

                return verb_start(strv_length(new_args), new_args, userdata);
        }

        return 0;
}
