/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "ansi-color.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "fileio.h"
#include "install.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "verbs.h"

static bool arg_quiet = false;
static bool arg_stdin = false;
static bool arg_dry_run = false;

static int help(void) {
        printf("%s [OPTIONS...] COMMAND [UNITS...]\n"
               "\n%sHelper tool for package manager integration.%s\n"
               "\n%sCommands:%s\n"
               "  install-system-units UNIT...      Enable and preset system units\n"
               "  install-user-units UNIT...        Enable and preset user units\n"
               "  remove-system-units UNIT...       Disable and stop system units\n"
               "  remove-user-units UNIT...         Disable and stop user units\n"
               "  mark-restart-system-units UNIT... Mark system units for restart\n"
               "  mark-reload-system-units UNIT...  Mark system units for reload\n"
               "  mark-restart-user-units UNIT...   Mark user units for restart\n"
               "  mark-reload-user-units UNIT...    Mark user units for reload\n"
               "  system-reload-restart             Reload configuration and restart marked\n"
               "  system-reload                     Reload configuration\n"
               "  system-restart                    Restart marked units\n"
               "  user-reload-restart               Reload and restart for user instances\n"
               "  user-reload                       Reload user instances\n"
               "  user-restart                      Restart marked user units\n"
               "  user-reexec                       Reexecute user instances\n"
               "\n%sOptions:%s\n"
               "  -h --help                         Show this help\n"
               "     --version                      Show version\n"
               "     --quiet                        Suppress error logging in some scenarios\n"
               "     --stdin                        Read unit file paths from standard input\n"
               "     --dry-run                      Only print what would be done\n"
               "\nSee the %s(8) man page for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_QUIET,
                ARG_STDIN,
                ARG_DRY_RUN,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                { "quiet",   no_argument, NULL, 'q'         },
                { "stdin",   no_argument, NULL, ARG_STDIN   },
                { "dry-run", no_argument, NULL, ARG_DRY_RUN },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hq", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_QUIET:
                        arg_quiet = true;
                        break;

                case ARG_STDIN:
                        arg_stdin = true;
                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int list_units(sd_bus *bus, char **patterns, char ***ret) {
        _cleanup_strv_free_ char **units = NULL;
        int r;

        assert(ret);

        if (strv_isempty(patterns)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsByPatterns");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, NULL);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, patterns);
        if (r < 0)
                return bus_log_create_error(r);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to list units by patterns: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        const char *id, *state, *substate;
        while ((r = sd_bus_message_read(
                                reply, "(ssssssouso)",
                                &id, NULL, NULL, &state, &substate, NULL, NULL, NULL, NULL, NULL)) > 0) {
                if (STR_IN_SET(state, "inactive", "dead", "failed")) {
                        log_debug("Unit %s is %s/%s, ignoring it.", id, state, substate);
                        continue;
                }

                if (strv_extend(&units, id) < 0)
                        return log_oom();
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        *ret = TAKE_PTR(units);
        return 0;
}

static int read_unit_paths_from_stdin(char ***ret) {
        _cleanup_strv_free_ char **units = NULL;
        int r;

        assert(ret);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                r = read_line(stdin, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read path from stdin: %m");
                if (r == 0)
                        break;

                if (!path_is_safe(line)) {
                        log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid unit file path '%s', ignoring", line);
                        continue;
                }

                _cleanup_free_ char *absolute = path_make_absolute(line, "/");
                if (!absolute)
                        return log_oom();

                _cleanup_free_ char *d = NULL, *f = NULL;
                r = path_extract_directory(absolute, &d);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract directory from '%s', ignoring: %m", absolute);
                        continue;
                }

                if (!PATH_IN_SET(d, SYSTEM_DATA_UNIT_DIR, USER_DATA_UNIT_DIR)) {
                        log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Path '%s' is outside of systemd unit directories, ignoring", d);
                        continue;
                }

                r = path_extract_filename(absolute, &f);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract filename from '%s', ignoring: %m", absolute);
                        continue;
                }

                struct stat st;
                if (stat(absolute, &st) < 0) {
                        log_debug_errno(errno, "Failed to stat '%s', ignoring: %m", absolute);
                        continue;
                }

                if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
                        log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'%s' is not a regular file, ignoring", absolute);
                        continue;
                }

                r = strv_consume(&units, TAKE_PTR(f));
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(units);
        return 0;
}

static int finalize_units(int argc, char **argv, char ***ret) {
        _cleanup_strv_free_ char **units = NULL;
        int r;

        assert(ret);

        if (arg_stdin) {
                r = read_unit_paths_from_stdin(&units);
                if (r < 0)
                        return r;
        } else {
                units = strv_copy(strv_skip(argv, 1));
                if (!units)
                        return log_oom();

                if (strv_isempty(units))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s expects at least a single unit argument", argv[0]);

                STRV_FOREACH(unit, units)
                        if (!unit_name_is_valid(*unit, UNIT_NAME_ANY))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s is not a valid unit name", *unit);
        }

        *ret = TAKE_PTR(units);
        return !strv_isempty(*ret);
}

static int expand_template_units(sd_bus *bus, char **units, char ***ret) {
        _cleanup_strv_free_ char **sv = NULL, **globs = NULL, **expanded = NULL;
        int r;

        assert(ret);

        STRV_FOREACH(unit, units) {
                UnitNameFlags flags = unit_name_classify(*unit);
                if (flags == -EINVAL) {
                        log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a valid unit name, ignoring", *unit);
                        continue;
                }
                if (flags < 0)
                        return flags;

                if (flags & UNIT_NAME_TEMPLATE) {
                        _cleanup_free_ char *glob = NULL;

                        r = unit_name_replace_instance_full(*unit, "*", /* accept_glob= */ true, &glob);
                        if (r < 0)
                                return log_error_errno(r, "Failed to turn template unit into glob: %m");

                        if (strv_consume(&globs, TAKE_PTR(glob)) < 0)
                                return log_oom();
                } else
                        if (strv_extend(&sv, *unit) < 0)
                                return log_oom();
        }

        r = list_units(bus, globs, &expanded);
        if (r < 0)
                return r;

        if (strv_extend_strv_consume(&sv, TAKE_PTR(expanded), /* filter_duplicates= */ true) < 0)
                return log_oom();

        *ret = TAKE_PTR(sv);
        return 0;
}

static bool offline(void) {
        if (running_in_chroot_or_offline())
                return true;

        if (sd_booted() <= 0)
                return true;

        return false;
}

static int bus_connect_user_unit(const char *unit, sd_bus **ret) {
        int r;

        assert(unit);
        assert(ret);

        _cleanup_free_ char *user = NULL;
        r = unit_name_to_instance(unit, &user);
        if (r < 0)
                return log_error_errno(r, "Failed to extract user id from unit '%s': %m", unit);

        _cleanup_free_ char *host = strjoin(user, "@");
        if (!host)
                return log_oom();

        r = bus_connect_transport(BUS_TRANSPORT_MACHINE, host, RUNTIME_SCOPE_USER, ret);
        if (r < 0)
                return bus_log_connect_full(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                            BUS_TRANSPORT_MACHINE, RUNTIME_SCOPE_USER);

        return 0;
}

static int install_units(int argc, char **argv, RuntimeScope scope) {
        int r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, &units);
        if (r <= 0)
                return r;

        if (offline() || scope == RUNTIME_SCOPE_GLOBAL) {
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                r = unit_file_preset(
                                RUNTIME_SCOPE_SYSTEM,
                                arg_dry_run ? UNIT_FILE_DRY_RUN : 0,
                                /* root_dir= */ NULL,
                                units,
                                UNIT_FILE_PRESET_FULL,
                                &changes,
                                &n_changes);

                install_changes_dump(r, "preset", changes, n_changes, /* quiet = */ true);
                return r;
        }

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "PresetUnitFiles");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, units);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "bb", false, false);
        if (r < 0)
                return bus_log_create_error(r);

        if (arg_dry_run)
                log_info("Would preset unit files with system service manager");
        else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
                if (r < 0)
                        return log_error_errno(r, "Failed to preset units: %s", bus_error_message(&error, r));

                r = sd_bus_message_skip(reply, "b");
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_deserialize_and_dump_unit_file_changes(reply, /* quiet= */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_install_system_units(int argc, char **argv, void *userdata) {
        return install_units(argc, argv, RUNTIME_SCOPE_SYSTEM);
}

static int verb_install_user_units(int argc, char **argv, void *userdata) {
        return install_units(argc, argv, RUNTIME_SCOPE_GLOBAL);
}

static int remove_units(int argc, char **argv, RuntimeScope scope) {
        int r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, &units);
        if (r <= 0)
                return r;

        if (offline() || scope == RUNTIME_SCOPE_GLOBAL) {
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                r = unit_file_disable(
                                scope,
                                (arg_dry_run ? UNIT_FILE_DRY_RUN : 0),
                                /* root_dir= */ NULL,
                                units,
                                &changes,
                                &n_changes);

                install_changes_dump(r, "disable", changes, n_changes, /* quiet = */ true);
                if (r < 0)
                        return r;

                if (offline())
                        return 0;
        }

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "DisableUnitFilesWithFlagsAndInstallInfo");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, units);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "t", UINT64_C(0));
                if (r < 0)
                        return bus_log_create_error(r);

                if (arg_dry_run)
                        log_info("Would disable unit files with system service manager");
                else {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
                        if (r < 0)
                                return log_error_errno(r, "Failed to disable units: %s", bus_error_message(&error, r));

                        r = sd_bus_message_skip(reply, "b");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = bus_deserialize_and_dump_unit_file_changes(reply, /* quiet= */ true);
                        if (r < 0)
                                return r;
                }

                _cleanup_strv_free_ char **expanded = NULL;
                r = expand_template_units(bus, units, &expanded);
                if (r < 0)
                        return r;

                _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");

                STRV_FOREACH(unit, expanded) {
                        if (arg_dry_run) {
                                log_info("Would stop unit %s in system service manager", *unit);
                                continue;
                        }

                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        r = bus_call_method(
                                        bus,
                                        bus_systemd_mgr,
                                        "StopUnit",
                                        &error,
                                        &reply,
                                        "ss", *unit, "replace");
                        if (r < 0) {
                                log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to stop unit %s, ignoring: %s",
                                               *unit, bus_error_message(&error, r));
                                continue;
                        }

                        const char *path;
                        r = sd_bus_message_read(reply, "o", &path);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = bus_wait_for_jobs_add(w, path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to watch job for %s: %m", *unit);
                }

                r = bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
                if (r < 0)
                        return r;
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                STRV_FOREACH(user, users) {
                        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;

                        r = bus_connect_user_unit(*user, &user_bus);
                        if (r < 0)
                                continue;

                        _cleanup_strv_free_ char **expanded = NULL;
                        r = expand_template_units(bus, units, &expanded);
                        if (r < 0)
                                return r;

                        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
                        r = bus_wait_for_jobs_new(user_bus, &w);
                        if (r < 0)
                                return log_error_errno(r, "Could not watch jobs: %m");

                        STRV_FOREACH(unit, expanded) {
                                if (arg_dry_run) {
                                        log_info("Would stop unit %s in user service manager %s", *unit, *user);
                                        continue;
                                }

                                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                                r = bus_call_method(
                                                user_bus,
                                                bus_systemd_mgr,
                                                "StopUnit",
                                                &error,
                                                &reply,
                                                "ss", *unit, "replace");
                                if (r < 0) {
                                        log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                                       "Failed to stop unit %s, ignoring: %s",
                                                       *unit, bus_error_message(&error, r));
                                        continue;
                                }

                                const char *path;
                                r = sd_bus_message_read(reply, "o", &path);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = bus_wait_for_jobs_add(w, path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to watch job for %s: %m", *unit);
                        }

                        r = bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int verb_remove_system_units(int argc, char **argv, void *userdata) {
        return remove_units(argc, argv, RUNTIME_SCOPE_SYSTEM);
}

static int verb_remove_user_units(int argc, char **argv, void *userdata) {
        return remove_units(argc, argv, RUNTIME_SCOPE_GLOBAL);
}

static int unit_set_property(sd_bus *bus, const char *unit, const char *property) {
        int r;

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties");
        if (r < 0)
                return bus_log_create_error(r);

        UnitType t = unit_name_to_type(unit);
        if (t < 0)
                return log_error_errno(t, "Invalid unit type: %s", unit);

        r = sd_bus_message_append(m, "sb", unit, false);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = bus_append_unit_property_assignment(m, t, property);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                "Failed to set property %s on %s, ignoring: %s",
                                property, unit, bus_error_message(&error, r));

        return 0;
}

static int set_markers(int argc, char **argv, RuntimeScope scope, UnitMarker marker) {
        char **units = strv_skip(argv, 1);
        int r;

        if (offline())
                return 0;

        _cleanup_free_ char *property = strjoin("Markers=+", unit_marker_to_string(marker));
        if (!property)
                return log_oom();

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                STRV_FOREACH(unit, units) {
                        if (arg_dry_run) {
                                log_info("Would set marker %s for unit %s in system service manager",
                                         unit_marker_to_string(marker), *unit);
                                continue;
                        }

                        r = unit_set_property(bus, *unit, property);
                        if (r < 0)
                                return r;
                }
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                STRV_FOREACH(user, users) {
                        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;

                        r = bus_connect_user_unit(*user, &user_bus);
                        if (r < 0)
                                continue;

                        STRV_FOREACH(unit, units) {
                                if (arg_dry_run) {
                                        log_info("Would set marker %s for unit %s in user service manager %s",
                                                unit_marker_to_string(marker), *unit, *user);
                                        continue;
                                }

                                r = unit_set_property(user_bus, *unit, property);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static int verb_mark_restart_system_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_SYSTEM, UNIT_MARKER_NEEDS_RESTART);
}

static int verb_mark_reload_system_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_SYSTEM, UNIT_MARKER_NEEDS_RELOAD);
}

static int verb_mark_restart_user_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_GLOBAL, UNIT_MARKER_NEEDS_RESTART);
}

static int verb_mark_reload_user_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_GLOBAL, UNIT_MARKER_NEEDS_RELOAD);
}

static int reload_restart(int argc, char **argv, RuntimeScope scope) {
        int r;

        if (offline())
                return 0;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                if (strstr(argv[0], "reload")) {
                        if (arg_dry_run)
                                log_info("Would reload system service manager");
                        else {
                                r = bus_service_manager_reload(bus);
                                if (r < 0)
                                        return r;
                        }
                }

                if (strstr(argv[0], "restart")) {
                        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;

                        r = bus_wait_for_jobs_new(bus, &w);
                        if (r < 0)
                                return log_error_errno(r, "Could not watch jobs: %m");

                        if (arg_dry_run)
                                log_info("Would enqueue marked jobs for system service manager");
                        else {
                                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                                r = bus_call_method(bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to enqueue marked jobs for service manager: %s",
                                                        bus_error_message(&error, r));

                                _cleanup_strv_free_ char **paths = NULL;
                                r = sd_bus_message_read_strv(reply, &paths);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                STRV_FOREACH(path, paths) {
                                        r = bus_wait_for_jobs_add(w, *path);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to watch job %s: %m", *path);
                                }
                        }

                        r = bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
                        if (r < 0)
                                return r;
                }
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                if (strstr(argv[0], "reload")) {
                        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;

                        r = bus_wait_for_jobs_new(bus, &w);
                        if (r < 0)
                                return log_error_errno(r, "Could not watch jobs: %m");

                        STRV_FOREACH(user, users) {
                                if (arg_dry_run) {
                                        log_info("Would reload user service manager %s", *user);
                                        continue;
                                }

                                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                                r = bus_call_method(
                                                bus,
                                                bus_systemd_mgr,
                                                "ReloadUnit",
                                                &error,
                                                &reply,
                                                "ss", *user, "replace");
                                if (r < 0) {
                                        log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                                       "Failed to reload user service manager %s, ignoring: %s",
                                                       *user, bus_error_message(&error, r));
                                        continue;
                                }

                                const char *path;
                                r = sd_bus_message_read(reply, "o", &path);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = bus_wait_for_jobs_add(w, path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to watch job for %s: %m", *user);
                        }

                        r = bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
                        if (r < 0)
                                return r;
                }

                if (strstr(argv[0], "restart")) {
                        STRV_FOREACH(user, users) {
                                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;

                                r = bus_connect_user_unit(*user, &user_bus);
                                if (r < 0)
                                        continue;

                                _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
                                r = bus_wait_for_jobs_new(user_bus, &w);
                                if (r < 0)
                                        return log_error_errno(r, "Could not watch jobs: %m");

                                if (arg_dry_run) {
                                        log_info("Would enqueue marked jobs for user service manager %s", *user);
                                        continue;
                                }

                                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                                r = bus_call_method(user_bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
                                if (r < 0) {
                                        log_full_errno(arg_quiet ? LOG_WARNING : LOG_DEBUG, r,
                                                       "Failed to enqueue marked jobs for user service manager %s, ignoring: %s",
                                                       *user, bus_error_message(&error, r));
                                        continue;
                                }

                                _cleanup_strv_free_ char **paths = NULL;
                                r = sd_bus_message_read_strv(reply, &paths);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                STRV_FOREACH(path, paths) {
                                        r = bus_wait_for_jobs_add(w, *path);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to watch job %s: %m", *path);
                                }

                                r = bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static int verb_system_reload_restart(int argc, char **argv, void *userdata) {
        return reload_restart(argc, argv, RUNTIME_SCOPE_SYSTEM);
}

static int verb_user_reload_restart(int argc, char **argv, void *userdata) {
        return reload_restart(argc, argv, RUNTIME_SCOPE_GLOBAL);
}

static int run(int argc, char *argv[]) {
        int r;

        static const Verb verbs[] = {
                { "install-system-units",      1, VERB_ANY, 0, verb_install_system_units      },
                { "install-user-units",        1, VERB_ANY, 0, verb_install_user_units        },
                { "remove-system-units",       1, VERB_ANY, 0, verb_remove_system_units       },
                { "remove-user-units",         1, VERB_ANY, 0, verb_remove_user_units         },
                { "mark-restart-system-units", 2, VERB_ANY, 0, verb_mark_restart_system_units },
                { "mark-reload-system-units",  2, VERB_ANY, 0, verb_mark_reload_system_units  },
                { "mark-restart-user-units",   2, VERB_ANY, 0, verb_mark_restart_user_units   },
                { "mark-reload-user-units",    2, VERB_ANY, 0, verb_mark_reload_user_units    },
                { "system-reload-restart",     1, 1,        0, verb_system_reload_restart     },
                { "system-reload",             1, 1,        0, verb_system_reload_restart     },
                { "system-restart",            1, 1,        0, verb_system_reload_restart     },
                { "user-reload-restart",       1, 1,        0, verb_user_reload_restart       },
                { "user-reload",               1, 1,        0, verb_user_reload_restart       },
                { "user-restart",              1, 1,        0, verb_user_reload_restart       },
                { "user-reexec",               1, 1,        0, verb_user_reload_restart       },
                {},
        };

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
