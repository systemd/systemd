/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-util.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "log.h"
#include "main-func.h"
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

STATIC_DESTRUCTOR_REGISTER(arg_names, freep); /* don't free the strings */

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cgls", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CGROUP...]\n\n"
               "Recursively show control group contents.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "  -a --all            Show all groups, including empty\n"
               "  -u --unit           Show the subtrees of specified system units\n"
               "     --user-unit      Show the subtrees of specified user units\n"
               "  -x --xattr=BOOL     Show cgroup extended attributes\n"
               "  -c --cgroup-id=BOOL Show cgroup ID\n"
               "  -l --full           Do not ellipsize output\n"
               "  -k                  Include kernel threads in output\n"
               "  -M --machine=NAME   Show container NAME\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_NO_PAGER = 0x100,
                ARG_VERSION,
                ARG_USER_UNIT,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "all",       no_argument,       NULL, 'a'           },
                { "full",      no_argument,       NULL, 'l'           },
                { "machine",   required_argument, NULL, 'M'           },
                { "unit",      optional_argument, NULL, 'u'           },
                { "user-unit", optional_argument, NULL, ARG_USER_UNIT },
                { "xattr",     required_argument, NULL, 'x'           },
                { "cgroup-id", required_argument, NULL, 'c'           },
                {}
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "-hkalM:u::xc", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 'a':
                        arg_output_flags |= OUTPUT_SHOW_ALL;
                        break;

                case 'u':
                        arg_show_unit = SHOW_UNIT_SYSTEM;
                        if (strv_push(&arg_names, optarg) < 0) /* push optarg if not empty */
                                return log_oom();
                        break;

                case ARG_USER_UNIT:
                        arg_show_unit = SHOW_UNIT_USER;
                        if (strv_push(&arg_names, optarg) < 0) /* push optarg if not empty */
                                return log_oom();
                        break;

                case 1:
                        /* positional argument */
                        if (strv_push(&arg_names, optarg) < 0)
                                return log_oom();
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'k':
                        arg_output_flags |= OUTPUT_KERNEL_THREADS;
                        break;

                case 'M':
                        arg_machine = optarg;
                        break;

                case 'x':
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --xattr= value: %s", optarg);
                        } else
                                r = true;

                        SET_FLAG(arg_output_flags, OUTPUT_CGROUP_XATTRS, r);
                        break;

                case 'c':
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --cgroup-id= value: %s", optarg);
                        } else
                                r = true;

                        SET_FLAG(arg_output_flags, OUTPUT_CGROUP_ID, r);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_machine && arg_show_unit != SHOW_UNIT_NONE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot combine --unit or --user-unit with --machine=.");

        return 1;
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

                                q = show_cgroup(*name, NULL, 0, arg_output_flags);
                        } else {
                                _cleanup_free_ char *p = NULL, *j = NULL;
                                const char *path;

                                if (!root) {
                                        /* Query root only if needed, treat error as fatal */
                                        r = show_cgroup_get_path_and_warn(arg_machine, NULL, &root);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to list cgroup tree: %m");
                                }

                                q = cg_split_spec(*name, /* ret_controller = */ NULL, &p);
                                if (q < 0) {
                                        log_error_errno(q, "Failed to split argument %s: %m", *name);
                                        goto failed;
                                }

                                if (p) {
                                        j = path_join(root, p);
                                        if (!j)
                                                return log_oom();

                                        path_simplify(j);
                                        path = j;
                                } else
                                        path = root;

                                printf("CGroup %s:\n", path);
                                fflush(stdout);

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

                                r = show_cgroup(cwd, NULL, 0, arg_output_flags);
                                done = true;
                        }
                }

                if (!done) {
                        _cleanup_free_ char *root = NULL;

                        r = show_cgroup_get_path_and_warn(arg_machine, NULL, &root);
                        if (r < 0)
                                return log_error_errno(r, "Failed to list cgroup tree: %m");

                        printf("CGroup %s:\n", root);
                        fflush(stdout);

                        printf("-.slice\n");
                        r = show_cgroup(root, NULL, 0, arg_output_flags);
                }
        }
        if (r < 0)
                return log_error_errno(r, "Failed to list cgroup tree: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
