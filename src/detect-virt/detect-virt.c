/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "confidential-virt.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
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
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-detect-virt", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sDetect execution in a virtualized environment.%s\n"
               "\nOptions:\n",
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
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Don't output anything, just set return value"):
                        arg_quiet = true;
                        break;

                OPTION('c', "container", NULL, "Only detect whether we are run in a container"):
                        arg_mode = ONLY_CONTAINER;
                        break;

                OPTION_LONG("private-users", NULL, "Only detect whether we are running in a user namespace"):
                        arg_mode = ONLY_PRIVATE_USERS;
                        break;

                OPTION('v', "vm", NULL, "Only detect whether we are run in a VM"):
                        arg_mode = ONLY_VM;
                        break;

                OPTION('r', "chroot", NULL, "Detect whether we are run in a chroot() environment"):
                        arg_mode = ONLY_CHROOT;
                        break;

                OPTION_LONG("list", NULL, "List all known and detectable types of virtualization"):
                        return DUMP_STRING_TABLE(virtualization, Virtualization, _VIRTUALIZATION_MAX);

                OPTION_LONG("cvm", NULL, "Only detect whether we are run in a confidential VM"):
                        arg_mode = ONLY_CVM;
                        return 1;

                OPTION_LONG("list-cvm", NULL, "List all known and detectable types of confidential virtualization"):
                        return DUMP_STRING_TABLE(confidential_virtualization, ConfidentialVirtualization, _CONFIDENTIAL_VIRTUALIZATION_MAX);
                }

        if (option_parser_get_n_args(&state) > 0)
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
