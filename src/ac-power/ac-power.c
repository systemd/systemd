/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "battery-util.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "option-parser.h"
#include "pretty-print.h"
#include "string-util.h"

#include "ac-power.options.inc"

static bool arg_verbose = false;

static enum {
        ACTION_AC_POWER,
        ACTION_LOW,
} arg_action = ACTION_AC_POWER;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-ac-power", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTION]\n"
               "\n%2$sReport whether we are connected to an external power source.%3$s\n\n"
               OPTION_HELP_GENERATED
               "\nSee the %4$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        FOREACH_OPTION(c, argc, argv, /* on_error= */ return c)
                switch (c) {

                case OPTION_HELP:
                        return help();

                case OPTION_VERSION:
                        return version();

                case OPTION_VERBOSE:
                        // option: -v --verbose
                        // help: Show state as text
                        arg_verbose = true;
                        break;

                case OPTION_LOW:
                        // help: Check if battery is discharging and low
                        arg_action = ACTION_LOW;
                        break;
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
