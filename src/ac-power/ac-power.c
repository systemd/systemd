/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-color.h"
#include "battery-util.h"
#include "build.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pretty-print.h"
#include "string-util.h"

static bool arg_verbose = false;

static enum {
        ACTION_AC_POWER,
        ACTION_LOW,
} arg_action = ACTION_AC_POWER;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-ac-power", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sReport whether we are connected to an external power source.%s\n"
               "\nOptions:\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        table_print(options, stdout);

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        assert(argc >= 0);
        assert(argv);

        OptionParser state = {};
        const char *arg;

        FOREACH_OPTION(&state, c, argc, argv, &arg, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('v', "verbose", NULL, "Show state as text"):
                        arg_verbose = true;
                        break;

                OPTION_LONG("low", NULL, "Check if battery is discharging and low"):
                        arg_action = ACTION_LOW;
                        break;
                }

        if (option_parser_get_n_args(&state, argc, argv) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

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
