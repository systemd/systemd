/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "build.h"
#include "confidential-virt.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-table.h"
#include "virt.h"

static bool arg_quiet = false;
static enum {
        ANY_VIRTUALIZATION,
        ONLY_VM,
        ONLY_CONTAINER,
        ONLY_CHROOT,
        ONLY_PRIVATE_USERS,
        ONLY_CVM,
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
               "     --cvm              Only detect whether we are run in a confidential VM\n"
               "  -q --quiet            Don't output anything, just set return value\n"
               "     --list             List all known and detectable types of virtualization\n"
               "     --list-cvm         List all known and detectable types of confidential \n"
               "                        virtualization\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_PRIVATE_USERS,
                ARG_LIST,
                ARG_CVM,
                ARG_LIST_CVM,
        };

        static const struct option options[] = {
                { "help",          no_argument, NULL, 'h'               },
                { "version",       no_argument, NULL, ARG_VERSION       },
                { "container",     no_argument, NULL, 'c'               },
                { "vm",            no_argument, NULL, 'v'               },
                { "chroot",        no_argument, NULL, 'r'               },
                { "private-users", no_argument, NULL, ARG_PRIVATE_USERS },
                { "quiet",         no_argument, NULL, 'q'               },
                { "cvm",           no_argument, NULL, ARG_CVM           },
                { "list",          no_argument, NULL, ARG_LIST          },
                { "list-cvm",      no_argument, NULL, ARG_LIST_CVM      },
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
                        DUMP_STRING_TABLE(virtualization, Virtualization, _VIRTUALIZATION_MAX);
                        return 0;

                case ARG_CVM:
                        arg_mode = ONLY_CVM;
                        return 1;

                case ARG_LIST_CVM:
                        DUMP_STRING_TABLE(confidential_virtualization, ConfidentialVirtualization, _CONFIDENTIAL_VIRTUALIZATION_MAX);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static int run(int argc, char *argv[]) {
        Virtualization v;
        ConfidentialVirtualization c;
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether we are being run in a virtualized
         * environment or not */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        switch (arg_mode) {
        case ONLY_VM:
                v = detect_vm();
                if (v < 0)
                        return log_error_errno(v, "Failed to check for VM: %m");
                break;

        case ONLY_CONTAINER:
                v = detect_container();
                if (v < 0)
                        return log_error_errno(v, "Failed to check for container: %m");
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

        case ONLY_CVM:
                c = detect_confidential_virtualization();
                if (c < 0)
                        return log_error_errno(c, "Failed to check for confidential virtualization: %m");
                if (!arg_quiet)
                        puts(confidential_virtualization_to_string(c));
                return c == CONFIDENTIAL_VIRTUALIZATION_NONE;

        case ANY_VIRTUALIZATION:
        default:
                v = detect_virtualization();
                if (v < 0)
                        return log_error_errno(v, "Failed to check for virtualization: %m");
        }

        if (!arg_quiet)
                puts(virtualization_to_string(v));

        return v == VIRTUALIZATION_NONE;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
