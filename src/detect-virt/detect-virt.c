/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-table.h"
#include "util.h"
#include "virt.h"

static bool arg_quiet = false;
static enum {
        ANY_VIRTUALIZATION,
        ONLY_VM,
        ONLY_CONTAINER,
        ONLY_CHROOT,
        ONLY_PRIVATE_USERS,
} arg_mode = ANY_VIRTUALIZATION;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-detect-virt", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Detect execution in a virtualized environment.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -c --container        Only detect whether we are run in a container\n"
               "  -v --vm               Only detect whether we are run in a VM\n"
               "  -r --chroot           Detect whether we are run in a chroot() environment\n"
               "     --private-users    Only detect whether we are running in a user namespace\n"
               "  -q --quiet            Don't output anything, just set return value\n"
               "     --list             List all known and detectable types of virtualization\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_PRIVATE_USERS,
                ARG_LIST,
        };

        static const struct option options[] = {
                { "help",          no_argument, NULL, 'h'               },
                { "version",       no_argument, NULL, ARG_VERSION       },
                { "container",     no_argument, NULL, 'c'               },
                { "vm",            no_argument, NULL, 'v'               },
                { "chroot",        no_argument, NULL, 'r'               },
                { "private-users", no_argument, NULL, ARG_PRIVATE_USERS },
                { "quiet",         no_argument, NULL, 'q'               },
                { "list",          no_argument, NULL, ARG_LIST          },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqcvr", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case 'c':
                        arg_mode = ONLY_CONTAINER;
                        break;

                case ARG_PRIVATE_USERS:
                        arg_mode = ONLY_PRIVATE_USERS;
                        break;

                case 'v':
                        arg_mode = ONLY_VM;
                        break;

                case 'r':
                        arg_mode = ONLY_CHROOT;
                        break;

                case ARG_LIST:
                        DUMP_STRING_TABLE(virtualization, int, _VIRTUALIZATION_MAX);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether we are being run in a virtualized
         * environment or not */

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        switch (arg_mode) {
        case ONLY_VM:
                r = detect_vm();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for VM: %m");
                break;

        case ONLY_CONTAINER:
                r = detect_container();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for container: %m");
                break;

        case ONLY_CHROOT:
                r = running_in_chroot();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for chroot() environment: %m");
                return !r;

        case ONLY_PRIVATE_USERS:
                r = running_in_userns();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for user namespace: %m");
                return !r;

        case ANY_VIRTUALIZATION:
        default:
                r = detect_virtualization();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for virtualization: %m");
                break;
        }

        if (!arg_quiet)
                puts(virtualization_to_string(r));

        return r == VIRTUALIZATION_NONE;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
