/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "battery-util.h"
#include "build.h"
#include "main-func.h"

static bool arg_verbose = false;

static enum {
        ACTION_AC_POWER,
        ACTION_LOW,
} arg_action = ACTION_AC_POWER;

static void help(void) {
        printf("%s\n\n"
               "Report whether we are connected to an external power source.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -v --verbose          Show state as text\n"
               "     --low              Check if battery is discharging and low\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_LOW,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                { "verbose", no_argument, NULL, 'v'         },
                { "low",     no_argument, NULL, ARG_LOW     },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hv", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case 'v':
                        arg_verbose = true;
                        break;

                case ARG_LOW:
                        arg_action = ACTION_LOW;
                        break;

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
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether AC power is plugged in or not. */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_action == ACTION_AC_POWER) {
                r = on_ac_power();
                if (r < 0)
                        return log_error_errno(r, "Failed to read AC status: %m");
        } else {
                r = battery_is_discharging_and_low();
                if (r < 0)
                        return log_error_errno(r, "Failed to read battery discharging + low status: %m");
        }

        if (arg_verbose)
                puts(yes_no(r));

        return r == 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
