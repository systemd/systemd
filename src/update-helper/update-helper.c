/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-future.h"

#include "ansi-color.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "cleanup-util.h"
#include "fileio.h"
#include "install.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-name.h"
#include "user-util.h"
#include "verbs.h"

#define USER_BUS_HELLO_TIMEOUT (10 * USEC_PER_SEC)

static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static bool arg_quiet = false;
static bool arg_stdin = false;
static bool arg_dry_run = false;

static int help(void) {
        printf("%1$s [OPTIONS...] COMMAND [UNITS...]\n\n"
               "%2$sHelper tool for package manager integration.%3$s\n"
               "\n%2$sOptions:%3$s\n"
               "  -h --help                         Show this help\n"
               "     --version                      Show version\n"
               "     --system                       Operate on system manager\n"
               "     --global                       Operate on user managers\n"
               "     --quiet                        Suppress error logging in some scenarios\n"
               "     --stdin                        Read unit file paths from standard input\n"
               "     --dry-run                      Only print what would be done\n"
               "\n%2$sCommands:%3$s\n"
               "  install-units UNIT...             Enable and preset units\n"
               "  remove-units UNIT...              Disable and stop units\n"
               "  mark-restart-units UNIT...        Mark units for restart\n"
               "  mark-reload-units UNIT...         Mark units for reload\n"
               "  daemon-reload                     Reload manager configuration\n"
               "  enqueue-marked                    Enqueue marked units\n"
               "  daemon-reload-enqueue-marked      Reload configuration and enqueue marked units\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_STDIN,
                ARG_DRY_RUN,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                { "system",  no_argument, NULL, ARG_SYSTEM  },
                { "global",  no_argument, NULL, ARG_GLOBAL  },
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

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                case 'q':
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
        r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
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
                        log_debug("Unit '%s' is %s/%s, ignoring it.", id, state, substate);
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

static int parse_unit(const char *s, RuntimeScope scope, bool fatal, char **ret) {
        int priority = fatal ? LOG_ERR : LOG_DEBUG;
        const char *suffix = fatal ? "" : ", ignoring";
        int r;

        assert(s);
        assert(ret);

        if (!path_is_absolute(s)) {
                if (!unit_name_is_valid(s, UNIT_NAME_ANY))
                        return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                              "'%s' is not a valid unit name%s", s, suffix);

                if (strdup_to(ret, s) < 0)
                        return log_oom_full(priority);

                return 0;
        }

        if (!path_is_safe(s))
                return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                      "Invalid unit file path '%s'%s", s, suffix);

        _cleanup_free_ char *d = NULL, *f = NULL;
        r = path_extract_directory(s, &d);
        if (r < 0)
                return log_full_errno(priority, r, "Failed to extract directory from '%s'%s: %m", s, suffix);

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                if (!PATH_IN_SET(d, SYSTEM_DATA_UNIT_DIR, SYSTEM_CONFIG_UNIT_DIR))
                        return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                        "'%s' is outside of the systemd system unit directories%s", s, suffix);
        } else
                if (!PATH_IN_SET(d, USER_DATA_UNIT_DIR, USER_CONFIG_UNIT_DIR))
                        return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                        "'%s' is outside of the systemd user unit directories%s", s, suffix);

        r = path_extract_filename(s, &f);
        if (r < 0)
                return log_full_errno(priority, r, "Failed to extract filename from '%s'%s: %m", s, suffix);

        struct stat st;
        r = RET_NERRNO(stat(s, &st));
        if (r >= 0 && (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
                return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                      "'%s' is not a regular file%s", s, suffix);
        else if (r < 0 && r != -ENOENT)
                return log_full_errno(priority, errno, "Failed to stat '%s'%s", s, suffix);

        if (!unit_name_is_valid(f, UNIT_NAME_ANY))
                return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                      "'%s' is not a valid unit name%s", f, suffix);

        *ret = TAKE_PTR(f);
        return 0;
}

static int finalize_units(int argc, char **argv, RuntimeScope scope, char ***ret) {
        _cleanup_strv_free_ char **units = NULL;
        int r;

        assert(ret);

        if (arg_stdin) {
                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        r = read_stripped_line(stdin, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read path from stdin: %m");
                        if (r == 0)
                                break;

                        _cleanup_free_ char *u = NULL;
                        r = parse_unit(line, scope, /* fatal= */ false, &u);
                        if (r < 0)
                                continue;

                        if (strv_consume(&units, TAKE_PTR(u)) < 0)
                                return log_oom();
                }
        } else {
                if (strv_isempty(strv_skip(argv, 1)))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s expects at least a single argument", argv[0]);

                STRV_FOREACH(s, strv_skip(argv, 1)) {
                        _cleanup_free_ char *u = NULL;

                        r = parse_unit(*s, scope, /* fatal= */ true, &u);
                        if (r < 0)
                                return r;

                        if (strv_consume(&units, TAKE_PTR(u)) < 0)
                                return log_oom();
                }
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
                        log_debug("'%s' is not a valid unit name, ignoring", *unit);
                        continue;
                }
                if (flags < 0)
                        return log_error_errno(flags, "Failed to classify '%s' as a unit name", *unit);

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

        r = parse_uid(user, NULL);
        if (r < 0)
                return log_error_errno(r, "User id of user service manager unit %s is not a valid UID: %m", user);

        _cleanup_free_ char *host = strjoin(user, "@");
        if (!host)
                return log_oom();

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_transport(BUS_TRANSPORT_MACHINE, host, RUNTIME_SCOPE_USER, &bus);
        if (r < 0) {
                (void) bus_log_connect_full(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                            BUS_TRANSPORT_MACHINE, RUNTIME_SCOPE_USER);
                *ret = NULL;
                return 0;
        }

        r = sd_bus_set_exit_on_disconnect(bus, false);
        if (r < 0)
                return r;

        /* Wait here for the bus connection to get established, so we don't have to deal with errors
         * establishing a connection to a user bus when we do the first method call. It also allows us to
         * put a lower timeout on establishing the connection without having to mess with the per method
         * call timeout. */
        for (usec_t n = now(CLOCK_MONOTONIC);;) {
                r = sd_bus_process(bus, /* ret= */ NULL);
                if (r > 0)
                        continue;
                if (r < 0) {
                        (void) log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                              "Failed to process bus, ignoring: %m");
                        break;
                }

                if (sd_bus_is_ready(bus))
                        break;
                if (!sd_bus_is_open(bus)) {
                        (void) log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, SYNTHETIC_ERRNO(ENOTCONN),
                                              "Failed to connect to bus, ignoring");
                        break;
                }

                uint64_t passed = now(CLOCK_MONOTONIC) - n;
                if (passed > USER_BUS_HELLO_TIMEOUT) {
                        (void) log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, SYNTHETIC_ERRNO(ETIMEDOUT),
                                              "Timed out connecting to bus, ignoring");
                        break;
                }

                r = sd_bus_wait(bus, USER_BUS_HELLO_TIMEOUT - passed);
                if (r == 0) {
                        (void) log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, SYNTHETIC_ERRNO(ETIMEDOUT),
                                              "Timed out connecting to bus, ignoring");
                        break;
                }
                if (r < 0) {
                        (void) log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                              "Failed to wait for bus, ignoring: %m");
                        break;
                }
        }

        *ret = r >= 0 ? TAKE_PTR(bus) : NULL;
        return r >= 0;
}

typedef struct UserUnitOperationArgs {
        char **units;
        UnitMarker marker;
} UserUnitOperationArgs;

typedef int (*UserUnitOperationFunc)(const char *user, const UserUnitOperationArgs *args);

typedef struct UserUnitOperation {
        char *user;
        UserUnitOperationFunc func;
        const UserUnitOperationArgs *args;
} UserUnitOperation;

static int user_unit_operation_fiber(void *userdata) {
        UserUnitOperation *o = ASSERT_PTR(userdata);
        return o->func(o->user, o->args);
}

static int user_units_operation(char **users, UserUnitOperationFunc func, const UserUnitOperationArgs *args) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        sd_future **fibers = NULL;
        size_t n_fibers = 0;
        int r;

        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        r = sd_event_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to create new event loop: %m");

        r = sd_event_set_exit_on_idle(e, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-idle for new event loop: %m");

        STRV_FOREACH(user, users) {
                _cleanup_(sd_future_unrefp) sd_future *f = NULL;

                _cleanup_free_ UserUnitOperation *o = new(UserUnitOperation, 1);
                if (!o)
                        return -ENOMEM;

                *o = (UserUnitOperation) {
                        .user = *user,
                        .func = func,
                        .args = args,
                };

                r = sd_future_new_fiber(e, *user, user_unit_operation_fiber, o, free, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to create new fiber for '%s': %m", *user);

                TAKE_PTR(o);

                if (!GREEDY_REALLOC(fibers, n_fibers + 1))
                        return log_oom();

                fibers[n_fibers++] = TAKE_PTR(f);
        }

        r = sd_event_loop(e);
        if (r < 0)
                return log_error_errno(r, "Failed to run fibers: %m");

        return 0;
}

static int install_units(int argc, char **argv, RuntimeScope scope) {
        int r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, scope, &units);
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

                install_changes_dump(r, "preset", changes, n_changes, arg_quiet);
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
                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Would preset unit files");
        else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
                if (r >= 0) {
                        r = sd_bus_message_skip(reply, "b");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet);
                        if (r < 0)
                                return r;
                } else
                        log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to preset units via dbus, ignoring: %s",
                                       bus_error_message(&error, r));
        }

        return 0;
}

static int verb_install_units(int argc, char **argv, void *userdata) {
        return install_units(argc, argv, arg_runtime_scope);
}

static int verb_install_system_units(int argc, char **argv, void *userdata) {
        return install_units(argc, argv, RUNTIME_SCOPE_SYSTEM);
}

static int verb_install_user_units(int argc, char **argv, void *userdata) {
        return install_units(argc, argv, RUNTIME_SCOPE_GLOBAL);
}

static void install_changes_dump_graceful(int error, InstallChange *changes, size_t n_changes) {
        bool err_logged = false;
        int r;

        /* Like install_changes_dump(), but does not log about missing units. */

        FOREACH_ARRAY(i, changes, n_changes)
                if (i->type >= 0) {
                        if (!arg_quiet)
                                install_change_dump_success(i);
                } else if (i->type != -ENOENT) {
                        _cleanup_free_ char *err_message = NULL;

                        r = install_change_dump_error(i, &err_message, /* ret_bus_error = */ NULL);
                        if (r == -ENOMEM)
                                return (void) log_oom();
                        if (r < 0)
                                log_warning_errno(r, "Failed to disable unit %s via dbus, ignoring: %m", i->path);
                        else
                                log_warning_errno(i->type, "Failed to disable unit, ignoring: %s", err_message);
                }

        if (error < 0 && error != -ENOENT && !err_logged)
                log_error_errno(error, "Failed to disable units: %m");
}

static int user_stop_units(const char *user, const UserUnitOperationArgs *args) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;
        int r;

        assert(user);
        assert(args->units);

        r = bus_connect_user_unit(user, &user_bus);
        if (r <= 0)
                return r;

        _cleanup_strv_free_ char **expanded = NULL;
        r = expand_template_units(user_bus, args->units, &expanded);
        if (r < 0)
                return r;

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        r = bus_wait_for_jobs_new(user_bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        STRV_FOREACH(unit, expanded) {
                if (arg_dry_run) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Would stop unit '%s''", *unit);
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
                        if (r != -ENOENT)
                                log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to stop unit '%s', ignoring: %s",
                                               *unit, bus_error_message(&error, r));
                        continue;
                }

                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Stopping unit '%s'", *unit);

                const char *path;
                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_add(w, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch job '%s': %m", path);
        }

        (void) bus_wait_for_jobs(w, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_SUCCESS|BUS_WAIT_JOBS_LOG_ERROR);

        return 0;
}

static int remove_units(int argc, char **argv, RuntimeScope scope) {
        int r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, scope, &units);
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

                install_changes_dump_graceful(r, changes, n_changes);
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
                        log_info("Would disable unit files");
                else {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
                        if (r >= 0) {
                                r = sd_bus_message_skip(reply, "b");
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                InstallChange *changes = NULL;
                                size_t n_changes = 0;

                                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                                r = bus_deserialize_unit_file_changes(reply, &changes, &n_changes);
                                if (r < 0)
                                        return r;

                                install_changes_dump_graceful(/* error= */ 0, changes, n_changes);
                        } else if (r != -ENOENT)
                                log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to disable units via dbus, ignoring: %s",
                                               bus_error_message(&error, r));
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
                                log_info("Would stop unit '%s'", *unit);
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
                                if (r != -ENOENT)
                                        log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                                       "Failed to stop unit %s, ignoring: %s",
                                                       *unit, bus_error_message(&error, r));
                                continue;
                        }

                        log_info("Stopping unit '%s'", *unit);

                        const char *path;
                        r = sd_bus_message_read(reply, "o", &path);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = bus_wait_for_jobs_add(w, path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to watch job '%s': %m", path);
                }

                (void) bus_wait_for_jobs(w, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_SUCCESS|BUS_WAIT_JOBS_LOG_ERROR);
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                r = user_units_operation(users, user_stop_units, &(UserUnitOperationArgs) {
                        .units = units,
                });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_remove_units(int argc, char **argv, void *userdata) {
        return remove_units(argc, argv, arg_runtime_scope);
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

static int user_set_marker(const char *user, const UserUnitOperationArgs *args) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;
        int r;

        assert(user);
        assert(args->units);

        r = bus_connect_user_unit(user, &user_bus);
        if (r <= 0)
                return r;

        _cleanup_free_ char *property = strjoin("Markers=+", unit_marker_to_string(args->marker));
        if (!property)
                return log_oom();

        STRV_FOREACH(unit, args->units) {
                if (arg_dry_run) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                 "Would set marker '%s' for unit '%s'",
                                 unit_marker_to_string(args->marker), *unit);
                        continue;
                }

                r = unit_set_property(user_bus, *unit, property);
                if (r < 0)
                        return r;

                log_debug("Configured marker '%s' for unit '%s'", unit_marker_to_string(args->marker), *unit);
        }

        return 0;
}

static int set_markers(int argc, char **argv, RuntimeScope scope, UnitMarker marker) {
        int r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, scope, &units);
        if (r <= 0)
                return r;

        if (offline())
                return 0;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                _cleanup_free_ char *property = strjoin("Markers=+", unit_marker_to_string(marker));
                if (!property)
                        return log_oom();

                STRV_FOREACH(unit, units) {
                        if (arg_dry_run) {
                                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                         "Would configure marker '%s' for unit '%s'",
                                         unit_marker_to_string(marker), *unit);
                                continue;
                        }

                        r = unit_set_property(bus, *unit, property);
                        if (r < 0)
                                return r;

                        log_debug("Configured marker '%s' for unit '%s'", unit_marker_to_string(marker), *unit);
                }
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                r = user_units_operation(users, user_set_marker, &(UserUnitOperationArgs) {
                        .units = units,
                        .marker = marker,
                });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_mark_restart_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, arg_runtime_scope, UNIT_MARKER_NEEDS_RESTART);
}

static int verb_mark_restart_system_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_SYSTEM, UNIT_MARKER_NEEDS_RESTART);
}

static int verb_mark_restart_user_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_GLOBAL, UNIT_MARKER_NEEDS_RESTART);
}

static int verb_mark_reload_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, arg_runtime_scope, UNIT_MARKER_NEEDS_RELOAD);
}

static int verb_mark_reload_system_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_SYSTEM, UNIT_MARKER_NEEDS_RELOAD);
}

static int verb_mark_reload_user_units(int argc, char **argv, void *userdata) {
        return set_markers(argc, argv, RUNTIME_SCOPE_GLOBAL, UNIT_MARKER_NEEDS_RELOAD);
}

static int user_enqueue_marked(const char *user, const UserUnitOperationArgs *args) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;
        int r;

        r = bus_connect_user_unit(user, &user_bus);
        if (r <= 0)
                return r;

        if (arg_dry_run) {
                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Would enqueue marked jobs");
                return 0;
        }

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        r = bus_wait_for_jobs_new(user_bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = bus_call_method(user_bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
        if (r < 0) {
                log_full_errno(arg_quiet ? LOG_WARNING : LOG_DEBUG, r,
                               "Failed to enqueue marked jobs, ignoring: %s",
                               bus_error_message(&error, r));
                return 0;
        }

        _cleanup_strv_free_ char **paths = NULL;
        r = sd_bus_message_read_strv(reply, &paths);
        if (r < 0)
                return bus_log_parse_error(r);

        STRV_FOREACH(path, paths) {
                r = bus_wait_for_jobs_add(w, *path);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch job '%s': %m", *path);
        }

        (void) bus_wait_for_jobs(w, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR);

        return 0;
}

static int reload_daemon_enqueue_marked(int argc, char **argv, RuntimeScope scope) {
        int r;

        if (offline())
                return 0;

        bool reload = strstr(argv[0], "reload") || strstr(argv[0], "reexec");
        bool enqueue = strstr(argv[0], "restart") || strstr(argv[0], "enqueue");

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (scope == RUNTIME_SCOPE_SYSTEM) {
                if (reload) {
                        log_full(arg_dry_run && !arg_quiet ? LOG_INFO : LOG_DEBUG,
                                 "%s service manager", arg_dry_run ? "Would reload" : "Reloading");

                        if (!arg_dry_run) {
                                r = bus_service_manager_reload(bus);
                                if (r < 0)
                                        return r;
                        }
                }

                if (enqueue) {
                        if (arg_dry_run)
                                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                         "Would enqueue marked jobs");
                        else {
                                _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
                                r = bus_wait_for_jobs_new(bus, &w);
                                if (r < 0)
                                        return log_error_errno(r, "Could not watch jobs: %m");

                                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                                r = bus_call_method(bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
                                if (r >= 0) {
                                        log_debug("Enqueued marked jobs");

                                        _cleanup_strv_free_ char **paths = NULL;
                                        r = sd_bus_message_read_strv(reply, &paths);
                                        if (r < 0)
                                                return bus_log_parse_error(r);

                                        STRV_FOREACH(path, paths) {
                                                r = bus_wait_for_jobs_add(w, *path);
                                                if (r < 0)
                                                        return log_error_errno(r, "Failed to watch job '%s': %m", *path);
                                        }

                                        (void) bus_wait_for_jobs(w, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR);
                                } else
                                        log_full_errno(arg_quiet ? LOG_DEBUG : LOG_WARNING, r,
                                                       "Failed to enqueue marked jobs, ignoring: %s",
                                                       bus_error_message(&error, r));
                        }
                }
        } else {
                _cleanup_strv_free_ char **users = NULL;

                r = list_units(bus, STRV_MAKE("user@*.service"), &users);
                if (r < 0)
                        return r;

                if (reload) {
                        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;

                        r = bus_wait_for_jobs_new(bus, &w);
                        if (r < 0)
                                return log_error_errno(r, "Could not watch jobs: %m");

                        STRV_FOREACH(user, users) {
                                log_full(arg_dry_run && !arg_quiet ? LOG_INFO : LOG_DEBUG,
                                         "%s service manager", arg_dry_run ? "Would reload" : "Reloading");

                                if (arg_dry_run)
                                        continue;

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
                                                       "Failed to queue reload, ignoring: %s",
                                                       bus_error_message(&error, r));
                                        continue;
                                }

                                const char *path;
                                r = sd_bus_message_read(reply, "o", &path);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = bus_wait_for_jobs_add(w, path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to watch job '%s': %m", path);
                        }

                        (void) bus_wait_for_jobs(w, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR);
                }

                if (enqueue) {
                        r = user_units_operation(users, user_enqueue_marked, &(UserUnitOperationArgs) {});
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int verb_daemon_reload_enqueue_marked(int argc, char **argv, void *userdata) {
        return reload_daemon_enqueue_marked(argc, argv, arg_runtime_scope);
}

static int verb_system_reload_restart(int argc, char **argv, void *userdata) {
        return reload_daemon_enqueue_marked(argc, argv, RUNTIME_SCOPE_SYSTEM);
}

static int verb_user_reload_restart(int argc, char **argv, void *userdata) {
        return reload_daemon_enqueue_marked(argc, argv, RUNTIME_SCOPE_GLOBAL);
}

static int run(int argc, char *argv[]) {
        int r;

        static const Verb verbs[] = {
                { "install-units",                1, VERB_ANY, 0, verb_install_units                },
                { "remove-units",                 1, VERB_ANY, 0, verb_remove_units                 },
                { "mark-restart-units",           1, VERB_ANY, 0, verb_mark_restart_units           },
                { "mark-reload-units",            1, VERB_ANY, 0, verb_mark_reload_units            },
                { "daemon-reload",                1, 1,        0, verb_daemon_reload_enqueue_marked },
                { "enqueue-marked",               1, 1,        0, verb_daemon_reload_enqueue_marked },
                { "daemon-reload-enqueue-marked", 1, 1,        0, verb_daemon_reload_enqueue_marked },

                /* Deprecated, but kept around for backwards compat, these ignore the runtime scope. */
                { "install-system-units",         1, VERB_ANY, 0, verb_install_system_units         },
                { "install-user-units",           1, VERB_ANY, 0, verb_install_user_units           },
                { "remove-system-units",          1, VERB_ANY, 0, verb_remove_system_units          },
                { "remove-user-units",            1, VERB_ANY, 0, verb_remove_user_units            },
                { "mark-restart-system-units",    1, VERB_ANY, 0, verb_mark_restart_system_units    },
                { "mark-reload-system-units",     1, VERB_ANY, 0, verb_mark_reload_system_units     },
                { "mark-restart-user-units",      1, VERB_ANY, 0, verb_mark_restart_user_units      },
                { "mark-reload-user-units",       1, VERB_ANY, 0, verb_mark_reload_user_units       },
                { "system-reload-restart",        1, 1,        0, verb_system_reload_restart        },
                { "system-reload",                1, 1,        0, verb_system_reload_restart        },
                { "system-restart",               1, 1,        0, verb_system_reload_restart        },
                { "user-reload-restart",          1, 1,        0, verb_user_reload_restart          },
                { "user-reload",                  1, 1,        0, verb_user_reload_restart          },
                { "user-restart",                 1, 1,        0, verb_user_reload_restart          },
                { "user-reexec",                  1, 1,        0, verb_user_reload_restart          },
                {},
        };

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
