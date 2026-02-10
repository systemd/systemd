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

#include "detect-virt.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-detect-virt", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Detect execution in a virtualized environment.\n\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

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
