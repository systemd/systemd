/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-future.h"
#include "sd-json.h"

#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "chase.h"
#include "cleanup-util.h"
#include "dlopen-note.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
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

#define USER_BUS_TIMEOUT (UPDATE_HELPER_USER_TIMEOUT_SEC * USEC_PER_SEC)

typedef enum UpdateFlags {
        UPDATE_SCOPE_SYSTEM = 1 << 0,
        UPDATE_SCOPE_GLOBAL = 1 << 1,
        UPDATE_RELOAD       = 1 << 2,
        UPDATE_ENQUEUE      = 1 << 3,
} UpdateFlags;

static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;
static bool arg_quiet = false;
static bool arg_stdin = false;
static bool arg_dry_run = false;

COMMAND(
        "systemd-update-helper\0",
        "Helper tool for package manager integration.",
);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("system", NULL, "Operate on system manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("global", NULL, "Operate on user managers"):
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                OPTION('q', "quiet", NULL, "Only log errors"):
                        arg_quiet = true;
                        break;

                OPTION_LONG("stdin", NULL, "Read unit file paths from standard input"):
                        arg_stdin = true;
                        break;

                OPTION_LONG("dry-run", NULL, "Only print what would be done"):
                        arg_dry_run = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
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
        if (r == -ETIME) /* The caller logs that the deadline of the user manager operation expired. */
                return r;
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
        r = RET_NERRNO(lstat(s, &st));
        if (r >= 0 && (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
                return log_full_errno(priority, SYNTHETIC_ERRNO(EINVAL),
                                      "'%s' is not a regular file%s", s, suffix);
        else if (r < 0 && r != -ENOENT)
                return log_full_errno(priority, r, "Failed to stat '%s'%s: %m", s, suffix);

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

static int verb_scope(const char *verb, uintptr_t data, RuntimeScope *ret) {
        assert(verb);
        assert(ret);

        if (!(data & (UPDATE_SCOPE_SYSTEM|UPDATE_SCOPE_GLOBAL))) {
                *ret = arg_runtime_scope >= 0 ? arg_runtime_scope : RUNTIME_SCOPE_SYSTEM;
                return 0;
        }

        if (arg_runtime_scope >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb '%s' does not accept --system or --global.", verb);

        *ret = FLAGS_SET(data, UPDATE_SCOPE_SYSTEM) ? RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_GLOBAL;
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

        uid_t uid;
        r = parse_uid(user, &uid);
        if (r < 0)
                return log_error_errno(r, "User id of user service manager unit %s is not a valid UID: %m", user);

        _cleanup_free_ char *p = NULL;
        if (asprintf(&p, "/run/user/" UID_FMT "/systemd/private", uid) < 0)
                return log_oom();

        /* The user owns /run/user/UID and can replace the socket with a symlink to the private socket of
         * the system manager. Refuse symlinks and require that the user owns the socket. Otherwise the
         * method calls meant for the user manager could stop units of the system manager. */
        _cleanup_close_ int inode_fd = -EBADF;
        r = chase(p, /* root= */ NULL, CHASE_SAFE|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, &inode_fd);
        if (r < 0) {
                log_warning_errno(r, "Failed to open %s, ignoring: %m", p);
                *ret = NULL;
                return 0;
        }

        struct stat st;
        if (fstat(inode_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", p);

        if (!S_ISSOCK(st.st_mode) || st.st_uid != uid) {
                log_warning("%s is not a socket owned by UID " UID_FMT ", ignoring.", p, uid);
                *ret = NULL;
                return 0;
        }

        /* On the failure paths below, the bus may still be connecting when the cleanup runs.
         * sd_bus_flush() waits without a timeout until the connection is established. With a frozen user
         * manager, that wait never ends. No messages are queued yet, so closing without a flush loses
         * nothing. */
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        r = sd_bus_new(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        r = sd_bus_set_description(bus, unit);
        if (r < 0)
                return log_error_errno(r, "Failed to set bus description: %m");

        _cleanup_free_ char *address = strjoin("unix:path=", FORMAT_PROC_FD_PATH(inode_fd));
        if (!address)
                return log_oom();

        r = sd_bus_set_address(bus, address);
        if (r < 0)
                return log_error_errno(r, "Failed to set bus address: %m");

        r = sd_bus_start(bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to connect to %s, ignoring: %m", unit);
                *ret = NULL;
                return 0;
        }

        r = sd_bus_set_exit_on_disconnect(bus, false);
        if (r < 0)
                return r;

        /* Wait until the connection is established. A connection failure is then logged once here,
         * instead of as a failure of the first method call. */
        for (;;) {
                r = sd_bus_process(bus, /* ret= */ NULL);
                if (r < 0)
                        break;
                if (r > 0)
                        continue;

                if (sd_bus_is_ready(bus) > 0) {
                        *ret = TAKE_PTR(bus);
                        return 1;
                }

                r = sd_bus_wait(bus, UINT64_MAX);
                if (r < 0)
                        break;
        }

        if (r == -ETIME)
                log_warning("Timed out connecting to %s, ignoring.", unit);
        else
                log_warning_errno(r, "Failed to connect to %s, ignoring: %m", unit);

        *ret = NULL;
        return 0;
}

typedef struct ManagerOperation ManagerOperation;

typedef int (*ManagerOperationFunc)(sd_bus *bus, const ManagerOperation *op);

/* When the deadline of a user manager operation expires, only the next suspension point returns -ETIME.
 * Later suspension points wait without a deadline. The operations therefore return -ETIME from a method
 * call instead of ignoring it like other errors. */
struct ManagerOperation {
        ManagerOperationFunc func;
        char **units;
        UnitMarker marker;
};

static int manager_stop_units(sd_bus *bus, const ManagerOperation *op) {
        int r;

        assert(bus);
        assert(op);

        _cleanup_strv_free_ char **expanded = NULL;
        r = expand_template_units(bus, op->units, &expanded);
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
                if (r == -ETIME)
                        return r;
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to stop unit '%s', ignoring: %s",
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

        (void) bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_SUCCESS|BUS_WAIT_JOBS_LOG_ERROR);
        return 0;
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
        r = sd_bus_call(bus, m, /* usec= */ 0, &error, NULL);
        if (r == -ETIME)
                return r;
        if (r < 0)
                log_warning_errno(r, "Failed to set property %s on %s, ignoring: %s",
                                  property, unit, bus_error_message(&error, r));

        return 0;
}

static int manager_set_markers(sd_bus *bus, const ManagerOperation *op) {
        int r;

        assert(bus);
        assert(op);

        _cleanup_free_ char *property = strjoin("Markers=+", unit_marker_to_string(op->marker));
        if (!property)
                return log_oom();

        STRV_FOREACH(unit, op->units) {
                if (arg_dry_run) {
                        log_info("Would set marker '%s' on unit '%s'", unit_marker_to_string(op->marker), *unit);
                        continue;
                }

                r = unit_set_property(bus, *unit, property);
                if (r < 0)
                        return r;

                log_debug("Set marker '%s' on unit '%s'", unit_marker_to_string(op->marker), *unit);
        }

        return 0;
}

static int manager_enqueue_marked(sd_bus *bus, const ManagerOperation *op) {
        int r;

        assert(bus);

        if (arg_dry_run) {
                log_info("Would enqueue marked jobs");
                return 0;
        }

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = bus_call_method(bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
        if (r == -ETIME)
                return r;
        if (r < 0) {
                log_warning_errno(r, "Failed to enqueue marked jobs, ignoring: %s", bus_error_message(&error, r));
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

        (void) bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR);
        return 0;
}

typedef struct UserManagerOperation {
        const char *unit;
        const ManagerOperation *op;
} UserManagerOperation;

static int user_manager_operation_fiber(void *userdata) {
        UserManagerOperation *o = ASSERT_PTR(userdata);
        int r;

        /* A user manager that does not respond must not block the package manager. The deadline covers
         * connecting, the method calls, and waiting for the jobs. */
        _cleanup_(sd_fiber_timeout_unrefp) sd_future *deadline = sd_fiber_timeout(USER_BUS_TIMEOUT);
        if (!deadline)
                return log_oom();

        /* Every method call waits for its reply, so no message is left to flush at the end. A flush
         * after the deadline expired would wait without a deadline. */
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_user_unit(o->unit, &bus);
        if (r <= 0)
                return r;

        r = o->op->func(bus, o->op);

        /* The operations ignore the result of bus_wait_for_jobs(). r is therefore not -ETIME when the
         * deadline expires while waiting for the jobs. Check the timer instead. */
        if (sd_future_state(deadline) == SD_FUTURE_RESOLVED)
                return log_warning_errno(SYNTHETIC_ERRNO(ETIME), "Timed out operating on %s, ignoring.", o->unit);

        return r;
}

static int run_on_user_managers(sd_bus *system_bus, const ManagerOperation *op) {
        int r;

        assert(system_bus);
        assert(op);

        _cleanup_strv_free_ char **users = NULL;
        r = list_units(system_bus, STRV_MAKE("user@*.service"), &users);
        if (r < 0)
                return r;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *g = NULL;
        r = sd_future_group_new(sd_fiber_get_event(), &g);
        if (r < 0)
                return log_error_errno(r, "Failed to create future group: %m");

        /* A failure for one user, e.g. a user manager that does not respond, must not cancel the
         * operation for the other users. */
        r = sd_future_group_set_policy(g, SD_FUTURE_GROUP_WAIT_ALL|SD_FUTURE_GROUP_IGNORE_ERRORS);
        if (r < 0)
                return log_error_errno(r, "Failed to set future group policy: %m");

        STRV_FOREACH(user, users) {
                _cleanup_free_ UserManagerOperation *o = new(UserManagerOperation, 1);
                if (!o)
                        return log_oom();

                *o = (UserManagerOperation) {
                        .unit = *user,
                        .op = op,
                };

                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
                r = sd_fiber_new(sd_fiber_get_event(), *user, user_manager_operation_fiber, o, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to create new fiber for '%s': %m", *user);

                r = sd_fiber_set_destroy_callback(f, free);
                if (r < 0)
                        return log_error_errno(r, "Failed to set destroy callback of fiber for '%s': %m", *user);

                TAKE_PTR(o);

                r = sd_future_group_add(g, f);
                if (r < 0)
                        return log_error_errno(r, "Failed to add fiber to future group: %m");

                f = sd_future_unref(f);
        }

        r = sd_future_group_seal(g);
        if (r < 0)
                return log_error_errno(r, "Failed to seal future group: %m");

        r = sd_fiber_await(g);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for fibers: %m");

        r = sd_future_result(g);
        if (r < 0)
                return log_error_errno(r, "Failed to run fibers: %m");

        return 0;
}

static int run_on_managers(RuntimeScope scope, sd_bus *system_bus, const ManagerOperation *op) {
        assert(system_bus);
        assert(op);

        if (scope == RUNTIME_SCOPE_SYSTEM)
                return op->func(system_bus, op);

        return run_on_user_managers(system_bus, op);
}

VERB_FULL(verb_install_units, "install-units", "UNIT…\0", 1, VERB_ANY, 0, 0, "Enable and preset units");
VERB_FULL(verb_install_units, "install-system-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_install_units, "install-user-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_GLOBAL, NULL);
static int verb_install_units(int argc, char **argv, uintptr_t data, void *userdata) {
        RuntimeScope scope;
        int r;

        r = verb_scope(argv[0], data, &scope);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **units = NULL;
        r = finalize_units(argc, argv, scope, &units);
        if (r <= 0)
                return r;

        /* unit_file_preset() ignores UNIT_FILE_DRY_RUN and changes the symlinks anyway. PresetUnitFiles has
         * no flag for a dry run. */
        if (arg_dry_run) {
                STRV_FOREACH(unit, units)
                        log_info("Would preset unit '%s'", *unit);
                return 0;
        }

        if (offline() || scope == RUNTIME_SCOPE_GLOBAL) {
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                r = unit_file_preset(
                                scope,
                                /* file_flags= */ 0,
                                /* root_dir= */ NULL,
                                units,
                                UNIT_FILE_PRESET_FULL,
                                &changes,
                                &n_changes);

                install_changes_dump(r, "preset", changes, n_changes, /* quiet= */ false);
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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = sd_bus_call(bus, m, /* usec= */ 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to preset units: %s", bus_error_message(&error, r));

        r = sd_bus_message_skip(reply, "b");
        if (r < 0)
                return bus_log_parse_error(r);

        return bus_deserialize_and_dump_unit_file_changes(reply, /* quiet= */ false);
}

static void install_changes_dump_graceful(int error, InstallChange *changes, size_t n_changes) {
        bool err_logged = false;
        int r;

        /* Like install_changes_dump(), but does not log about missing units. */

        FOREACH_ARRAY(i, changes, n_changes)
                if (i->type >= 0)
                        install_change_dump_success(i);
                else if (i->type != -ENOENT) {
                        _cleanup_free_ char *err_message = NULL;

                        r = install_change_dump_error(i, &err_message, /* ret_bus_error = */ NULL);
                        if (r == -ENOMEM)
                                return (void) log_oom();
                        if (r < 0)
                                log_warning_errno(r, "Failed to disable unit %s, ignoring: %m", i->path);
                        else
                                log_warning_errno(i->type, "Failed to disable unit, ignoring: %s", err_message);

                        err_logged = true;
                }

        if (error < 0 && error != -ENOENT && !err_logged)
                log_warning_errno(error, "Failed to disable units, ignoring: %m");
}

VERB_FULL(verb_remove_units, "remove-units", "UNIT…\0", 1, VERB_ANY, 0, 0, "Disable and stop units");
VERB_FULL(verb_remove_units, "remove-system-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_remove_units, "remove-user-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_GLOBAL, NULL);
static int verb_remove_units(int argc, char **argv, uintptr_t data, void *userdata) {
        RuntimeScope scope;
        int r;

        r = verb_scope(argv[0], data, &scope);
        if (r < 0)
                return r;

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
                                log_warning_errno(r,
                                                  "Failed to disable units, ignoring: %s",
                                                  bus_error_message(&error, r));
                }
        }

        return run_on_managers(scope, bus, &(const ManagerOperation) {
                .func = manager_stop_units,
                .units = units,
        });
}

VERB_FULL(verb_mark_units, "mark-restart-units", "UNIT…\0", 1, VERB_ANY, 0, 0, "Mark units for restart");
VERB_FULL(verb_mark_units, "mark-restart-system-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_mark_units, "mark-restart-user-units", NULL, 1, VERB_ANY, 0, UPDATE_SCOPE_GLOBAL, NULL);
VERB_FULL(verb_mark_units, "mark-reload-units", "UNIT…\0", 1, VERB_ANY, 0, UPDATE_RELOAD, "Mark units for reload");
VERB_FULL(verb_mark_units, "mark-reload-system-units", NULL, 1, VERB_ANY, 0, UPDATE_RELOAD|UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_mark_units, "mark-reload-user-units", NULL, 1, VERB_ANY, 0, UPDATE_RELOAD|UPDATE_SCOPE_GLOBAL, NULL);
static int verb_mark_units(int argc, char **argv, uintptr_t data, void *userdata) {
        UnitMarker marker = FLAGS_SET(data, UPDATE_RELOAD) ? UNIT_MARKER_NEEDS_RELOAD : UNIT_MARKER_NEEDS_RESTART;
        RuntimeScope scope;
        int r;

        r = verb_scope(argv[0], data, &scope);
        if (r < 0)
                return r;

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

        return run_on_managers(scope, bus, &(const ManagerOperation) {
                .func = manager_set_markers,
                .units = units,
                .marker = marker,
        });
}

static int reload_user_managers(sd_bus *system_bus) {
        int r;

        assert(system_bus);

        _cleanup_strv_free_ char **users = NULL;
        r = list_units(system_bus, STRV_MAKE("user@*.service"), &users);
        if (r < 0)
                return r;

        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        r = bus_wait_for_jobs_new(system_bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        STRV_FOREACH(user, users) {
                if (arg_dry_run) {
                        log_info("Would reload %s", *user);
                        continue;
                }

                log_debug("Reloading %s", *user);

                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                r = bus_call_method(
                                system_bus,
                                bus_systemd_mgr,
                                "ReloadUnit",
                                &error,
                                &reply,
                                "ss", *user, "replace");
                if (r < 0) {
                        log_warning_errno(r, "Failed to queue reload of %s, ignoring: %s",
                                          *user, bus_error_message(&error, r));
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

        (void) bus_wait_for_jobs(w, BUS_WAIT_JOBS_LOG_ERROR);
        return 0;
}

VERB_FULL(verb_daemon_reload_enqueue_marked, "daemon-reload", NULL, 1, 1, 0, UPDATE_RELOAD, "Reload manager configuration");
VERB_FULL(verb_daemon_reload_enqueue_marked, "enqueue-marked", NULL, 1, 1, 0, UPDATE_ENQUEUE, "Enqueue marked units");
VERB_FULL(verb_daemon_reload_enqueue_marked, "daemon-reload-enqueue-marked", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_ENQUEUE, "Reload configuration and enqueue marked units");
VERB_FULL(verb_daemon_reload_enqueue_marked, "system-reload-restart", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_ENQUEUE|UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "system-reload", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "system-restart", NULL, 1, 1, 0, UPDATE_ENQUEUE|UPDATE_SCOPE_SYSTEM, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "user-reload-restart", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_ENQUEUE|UPDATE_SCOPE_GLOBAL, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "user-reload", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_SCOPE_GLOBAL, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "user-restart", NULL, 1, 1, 0, UPDATE_ENQUEUE|UPDATE_SCOPE_GLOBAL, NULL);
VERB_FULL(verb_daemon_reload_enqueue_marked, "user-reexec", NULL, 1, 1, 0, UPDATE_RELOAD|UPDATE_SCOPE_GLOBAL, NULL);
static int verb_daemon_reload_enqueue_marked(int argc, char **argv, uintptr_t data, void *userdata) {
        bool reload = FLAGS_SET(data, UPDATE_RELOAD), enqueue = FLAGS_SET(data, UPDATE_ENQUEUE);
        RuntimeScope scope;
        int r;

        r = verb_scope(argv[0], data, &scope);
        if (r < 0)
                return r;

        if (offline())
                return 0;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to private bus: %m");

        if (reload) {
                if (scope == RUNTIME_SCOPE_SYSTEM) {
                        if (arg_dry_run)
                                log_info("Would reload service manager");
                        else {
                                log_debug("Reloading service manager");

                                r = bus_service_manager_reload(bus);
                                if (r < 0)
                                        return r;
                        }
                } else {
                        r = reload_user_managers(bus);
                        if (r < 0)
                                return r;
                }
        }

        if (enqueue) {
                r = run_on_managers(scope, bus, &(const ManagerOperation) {
                        .func = manager_enqueue_marked,
                });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        LIBSELINUX_NOTE(recommended);

        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        /* $SYSTEMD_LOG_LEVEL=debug takes precedence over --quiet. */
        if (arg_quiet && log_get_max_level() < LOG_DEBUG)
                log_set_max_level(MIN(log_get_max_level(), LOG_ERR));

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION_FIBER(run);
