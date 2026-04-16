/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-util.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

static PagerFlags arg_pager_flags = 0;
static OutputFlags arg_output_flags = 0;

static enum {
        SHOW_UNIT_NONE,
        SHOW_UNIT_SYSTEM,
        SHOW_UNIT_USER,
} arg_show_unit = SHOW_UNIT_NONE;
static char **arg_names = NULL;

static int arg_full = -1;
static const char* arg_machine = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_names, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-cgls", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...] [CGROUP...]\n\n"
               "%sRecursively show control group contents.%s\n\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 1);
        assert(argv);

        OptionParser state = { argc, argv, OPTION_PARSER_RETURN_POSITIONAL_ARGS };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION('a', "all", NULL, "Show all groups, including empty"):
                        arg_output_flags |= OUTPUT_SHOW_ALL;
                        break;

                OPTION_FULL(OPTION_OPTIONAL_ARG, 'u', "unit", "UNIT",
                            "Show the subtrees of specified system units"):
                        if (arg_show_unit == SHOW_UNIT_USER)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                "Cannot combine --unit with --user-unit.");

                        arg_show_unit = SHOW_UNIT_SYSTEM;
                        if (strv_extend(&arg_names, arg) < 0) /* push arg if not empty */
                                return log_oom();
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "user-unit", "UNIT",
                                  "Show the subtrees of specified user units"):
                        if (arg_show_unit == SHOW_UNIT_SYSTEM)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                "Cannot combine --user-unit with --unit.");

                        arg_show_unit = SHOW_UNIT_USER;
                        if (strv_extend(&arg_names, arg) < 0) /* push arg if not empty */
                                return log_oom();
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "xattr", "BOOL",
                                  "Show cgroup extended attributes"): {}
                OPTION_SHORT('x', NULL, "Same as --xattr=true"):
                        if (arg) {
                                r = parse_boolean(arg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --xattr= value: %s", arg);
                        } else
                                r = true;

                        SET_FLAG(arg_output_flags, OUTPUT_CGROUP_XATTRS, r);
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "cgroup-id", "BOOL",
                                  "Show cgroup ID"): {}
                OPTION_SHORT('c', NULL, "Same as --cgroup-id=true"):
                        if (arg) {
                                r = parse_boolean(arg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --cgroup-id= value: %s", arg);
                        } else
                                r = true;

                        SET_FLAG(arg_output_flags, OUTPUT_CGROUP_ID, r);
                        break;

                OPTION('l', "full", NULL, "Do not ellipsize output"):
                        arg_full = true;
                        break;

                OPTION_SHORT('k', NULL, "Include kernel threads in output"):
                        arg_output_flags |= OUTPUT_KERNEL_THREADS;
                        break;

                OPTION_COMMON_MACHINE:
                        arg_machine = arg;
                        break;

                OPTION_POSITIONAL:
                        if (strv_extend(&arg_names, arg) < 0) /* push arg */
                                return log_oom();
                        break;
                }

        if (arg_machine && arg_show_unit != SHOW_UNIT_NONE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot combine --unit or --user-unit with --machine=.");

        assert(option_parser_get_n_args(&state) == 0);

        return 1;
}

static void show_cg_info(const char *path) {
        printf("CGroup %s:\n", empty_to_root(path));
        fflush(stdout);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        pager_open(arg_pager_flags);
        if (arg_full < 0 && pager_have())
                arg_full = true;

        if (arg_full > 0)
                arg_output_flags |= OUTPUT_FULL_WIDTH;

        if (arg_names) {
                _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _cleanup_free_ char *root = NULL;

                STRV_FOREACH(name, arg_names) {
                        int q;

                        if (arg_show_unit != SHOW_UNIT_NONE) {
                                /* Command line arguments are unit names */
                                _cleanup_free_ char *cgroup = NULL, *unit_name = NULL;

                                r = unit_name_mangle(*name, UNIT_NAME_MANGLE_WARN, &unit_name);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to mangle unit name: %m");

                                if (!bus) {
                                        RuntimeScope scope = arg_show_unit == SHOW_UNIT_USER ? RUNTIME_SCOPE_USER : RUNTIME_SCOPE_SYSTEM;

                                        /* Connect to the bus only if necessary */
                                        r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, scope, &bus);
                                        if (r < 0)
                                                return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL, scope);
                                }

                                q = show_cgroup_get_unit_path_and_warn(bus, unit_name, &cgroup);
                                if (q < 0)
                                        goto failed;

                                if (isempty(cgroup)) {
                                        q = log_warning_errno(SYNTHETIC_ERRNO(ENOENT), "Unit %s not found.", unit_name);
                                        goto failed;
                                }

                                printf("Unit %s (%s):\n", unit_name, cgroup);
                                fflush(stdout);

                                q = show_cgroup(cgroup, NULL, 0, arg_output_flags);

                        } else if (path_startswith(*name, "/sys/fs/cgroup")) {

                                printf("Directory %s:\n", *name);
                                fflush(stdout);

                                q = show_cgroup_by_path(*name, NULL, 0, arg_output_flags);
                        } else {
                                _cleanup_free_ char *c = NULL, *p = NULL, *j = NULL;
                                const char *path;

                                if (!root) {
                                        /* Query root only if needed, treat error as fatal */
                                        r = show_cgroup_get_path_and_warn(arg_machine, NULL, &root);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to list cgroup tree: %m");
                                }

                                q = cg_split_spec(*name, &c, &p);
                                if (q < 0) {
                                        log_error_errno(q, "Failed to split argument %s: %m", *name);
                                        goto failed;
                                }

                                if (c && !streq(c, SYSTEMD_CGROUP_CONTROLLER))
                                        log_warning("Legacy cgroup v1 controller '%s' was specified, ignoring.", c);

                                if (p) {
                                        j = path_join(root, p);
                                        if (!j)
                                                return log_oom();

                                        path_simplify(j);
                                        path = j;
                                } else
                                        path = root;

                                show_cg_info(path);

                                q = show_cgroup(path, NULL, 0, arg_output_flags);
                        }

                failed:
                        if (q < 0 && r >= 0)
                                r = q;
                }

        } else {
                bool done = false;

                if (!arg_machine)  {
                        _cleanup_free_ char *cwd = NULL;

                        r = safe_getcwd(&cwd);
                        if (r < 0)
                                return log_error_errno(r, "Cannot determine current working directory: %m");

                        if (path_startswith(cwd, "/sys/fs/cgroup")) {
                                printf("Working directory %s:\n", cwd);
                                fflush(stdout);

                                r = show_cgroup_by_path(cwd, NULL, 0, arg_output_flags);
                                done = true;
                        }
                }

                if (!done) {
                        _cleanup_free_ char *root = NULL;

                        r = show_cgroup_get_path_and_warn(arg_machine, NULL, &root);
                        if (r < 0)
                                return log_error_errno(r, "Failed to list cgroup tree: %m");

                        show_cg_info(root);

                        printf("-.slice\n");
                        r = show_cgroup(root, NULL, 0, arg_output_flags);
                }
        }
        if (r < 0)
                return log_error_errno(r, "Failed to list cgroup tree: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
