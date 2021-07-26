/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "all-units.h"
#include "analyze-verify.h"
#include "bus-error.h"
#include "bus-util.h"
#include "log.h"
#include "manager.h"
#include "pager.h"
#include "path-util.h"
#include "string-table.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-serialize.h"

static void log_syntax_callback(const char *unit, int level, void *userdata) {
        Set **s = userdata;
        int r;

        assert(userdata);
        assert(unit);

        if (level > LOG_WARNING)
                return;

        r = set_put_strdup(s, unit);
        if (r < 0) {
                set_free_free(*s);
                *s = POINTER_MAX;
        }
}

static int prepare_filename(const char *filename, char **ret) {
        int r;
        const char *name;
        _cleanup_free_ char *abspath = NULL;
        _cleanup_free_ char *dir = NULL;
        _cleanup_free_ char *with_instance = NULL;
        char *c;

        assert(filename);
        assert(ret);

        r = path_make_absolute_cwd(filename, &abspath);
        if (r < 0)
                return r;

        name = basename(abspath);
        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                r = unit_name_replace_instance(name, "i", &with_instance);
                if (r < 0)
                        return r;
        }

        dir = dirname_malloc(abspath);
        if (!dir)
                return -ENOMEM;

        c = path_join(dir, with_instance ?: name);
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

static int generate_path(char **var, char **filenames) {
        const char *old;
        char **filename;

        _cleanup_strv_free_ char **ans = NULL;
        int r;

        STRV_FOREACH(filename, filenames) {
                char *t;

                t = dirname_malloc(*filename);
                if (!t)
                        return -ENOMEM;

                r = strv_consume(&ans, t);
                if (r < 0)
                        return r;
        }

        assert_se(strv_uniq(ans));

        /* First, prepend our directories. Second, if some path was specified, use that, and
         * otherwise use the defaults. Any duplicates will be filtered out in path-lookup.c.
         * Treat explicit empty path to mean that nothing should be appended.
         */
        old = getenv("SYSTEMD_UNIT_PATH");
        if (!streq_ptr(old, "")) {
                if (!old)
                        old = ":";

                r = strv_extend(&ans, old);
                if (r < 0)
                        return r;
        }

        *var = strv_join(ans, ":");
        if (!*var)
                return -ENOMEM;

        return 0;
}

static int verify_socket(Unit *u) {
        Unit *service;
        int r;

        assert(u);

        if (u->type != UNIT_SOCKET)
                return 0;

        r = socket_load_service_unit(SOCKET(u), -1, &service);
        if (r < 0)
                return log_unit_error_errno(u, r, "service unit for the socket cannot be loaded: %m");

        if (service->load_state != UNIT_LOADED)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                            "service %s not loaded, socket cannot be started.", service->id);

        log_unit_debug(u, "using service unit %s.", service->id);
        return 0;
}

int verify_executable(Unit *u, const ExecCommand *exec, const char *root) {
        int r;

        if (!exec)
                return 0;

        if (exec->flags & EXEC_COMMAND_IGNORE_FAILURE)
                return 0;

        r = find_executable_full(exec->path, root, false, NULL, NULL);
        if (r < 0)
                return log_unit_error_errno(u, r, "Command %s is not executable: %m", exec->path);

        return 0;
}

static int verify_executables(Unit *u, const char *root) {
        ExecCommand *exec;
        int r = 0, k;
        unsigned i;

        assert(u);

        exec =  u->type == UNIT_SOCKET ? SOCKET(u)->control_command :
                u->type == UNIT_MOUNT ? MOUNT(u)->control_command :
                u->type == UNIT_SWAP ? SWAP(u)->control_command : NULL;
        k = verify_executable(u, exec, root);
        if (k < 0 && r == 0)
                r = k;

        if (u->type == UNIT_SERVICE)
                for (i = 0; i < ELEMENTSOF(SERVICE(u)->exec_command); i++) {
                        k = verify_executable(u, SERVICE(u)->exec_command[i], root);
                        if (k < 0 && r == 0)
                                r = k;
                }

        if (u->type == UNIT_SOCKET)
                for (i = 0; i < ELEMENTSOF(SOCKET(u)->exec_command); i++) {
                        k = verify_executable(u, SOCKET(u)->exec_command[i], root);
                        if (k < 0 && r == 0)
                                r = k;
                }

        return r;
}

static int verify_documentation(Unit *u, bool check_man) {
        char **p;
        int r = 0, k;

        STRV_FOREACH(p, u->documentation) {
                log_unit_debug(u, "Found documentation item: %s", *p);

                if (check_man && startswith(*p, "man:")) {
                        k = show_man_page(*p + 4, true);
                        if (k != 0) {
                                if (k < 0)
                                        log_unit_error_errno(u, k, "Can't show %s: %m", *p + 4);
                                else {
                                        log_unit_error(u, "Command 'man %s' failed with code %d", *p + 4, k);
                                        k = -ENOEXEC;
                                }
                                if (r == 0)
                                        r = k;
                        }
                }
        }

        /* Check remote URLs? */

        return r;
}

static int verify_unit(Unit *u, bool check_man, const char *root) {
        _cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;
        int r, k;

        assert(u);

        if (DEBUG_LOGGING)
                unit_dump(u, stdout, "\t");

        log_unit_debug(u, "Creating %s/start job", u->id);
        r = manager_add_job(u->manager, JOB_START, u, JOB_REPLACE, NULL, &err, NULL);
        if (r < 0)
                log_unit_error_errno(u, r, "Failed to create %s/start: %s", u->id, bus_error_message(&err, r));

        k = verify_socket(u);
        if (k < 0 && r == 0)
                r = k;

        k = verify_executables(u, root);
        if (k < 0 && r == 0)
                r = k;

        k = verify_documentation(u, check_man);
        if (k < 0 && r == 0)
                r = k;

        return r;
}

static void set_destroy_ignore_pointer_max(Set** s) {
        if (*s == POINTER_MAX)
                return;
        set_free_free(*s);
}

int verify_units(char **filenames, UnitFileScope scope, bool check_man, bool run_generators, RecursiveErrors recursive_errors, const char *root) {
        const ManagerTestRunFlags flags =
                MANAGER_TEST_RUN_MINIMAL |
                MANAGER_TEST_RUN_ENV_GENERATORS |
                (recursive_errors == RECURSIVE_ERRORS_NO) * MANAGER_TEST_RUN_IGNORE_DEPENDENCIES |
                run_generators * MANAGER_TEST_RUN_GENERATORS;

        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(set_destroy_ignore_pointer_max) Set *s = NULL;
        _unused_ _cleanup_(clear_log_syntax_callback) dummy_t dummy;
        Unit *units[strv_length(filenames)];
        _cleanup_free_ char *var = NULL;
        int r, k, i, count = 0;
        char **filename;

        if (strv_isempty(filenames))
                return 0;

        /* Allow systemd-analyze to hook in a callback function so that it can get
         * all the required log data from the function itself without having to rely
         * on a global set variable for the same */
        set_log_syntax_callback(log_syntax_callback, &s);

        /* set the path */
        r = generate_path(&var, filenames);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit load path: %m");

        assert_se(set_unit_path(var) >= 0);

        r = manager_new(scope, flags, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");

        r = manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, root);
        if (r < 0)
                return r;

        manager_clear_jobs(m);

        log_debug("Loading remaining units from the command line...");

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *prepared = NULL;

                log_debug("Handling %s...", *filename);

                k = prepare_filename(*filename, &prepared);
                if (k < 0) {
                        log_error_errno(k, "Failed to prepare filename %s: %m", *filename);
                        if (r == 0)
                                r = k;
                        continue;
                }

                k = manager_load_startable_unit_or_warn(m, NULL, prepared, &units[count]);
                if (k < 0) {
                        if (r == 0)
                                r = k;
                        continue;
                }

                count++;
        }

        for (i = 0; i < count; i++) {
                k = verify_unit(units[i], check_man, root);
                if (k < 0 && r == 0)
                        r = k;
        }

        if (s == POINTER_MAX)
                return log_oom();

        if (set_isempty(s) || r != 0)
                return r;

        /* If all previous verifications succeeded, then either the recursive parsing of all the
         * associated dependencies with RECURSIVE_ERRORS_YES or the parsing of the specified unit file
         * with RECURSIVE_ERRORS_NO must have yielded a syntax warning and hence, a non-empty set. */
        if (IN_SET(recursive_errors, RECURSIVE_ERRORS_YES, RECURSIVE_ERRORS_NO))
                return -ENOTRECOVERABLE;

        /* If all previous verifications succeeded, then the non-empty set could have resulted from
         * a syntax warning encountered during the recursive parsing of the specified unit file and
         * its direct dependencies. Hence, search for any of the filenames in the set and if found,
         * return a non-zero process exit status. */
        if (recursive_errors == RECURSIVE_ERRORS_ONE)
                STRV_FOREACH(filename, filenames)
                        if (set_contains(s, basename(*filename)))
                                return -ENOTRECOVERABLE;

        return 0;
}

static const char* const recursive_errors_table[_RECURSIVE_ERRORS_MAX] = {
        [RECURSIVE_ERRORS_NO]  = "no",
        [RECURSIVE_ERRORS_YES] = "yes",
        [RECURSIVE_ERRORS_ONE] = "one",
};

DEFINE_STRING_TABLE_LOOKUP(recursive_errors, RecursiveErrors);
