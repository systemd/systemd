/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "build.h"
#include "log.h"
#include "main-func.h"
#include "sleep-config.h"

static void help(void) {
        printf("%s\n\n"
               "Checks battery level to see whether there's enough charge.\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char * argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no argument.",
                                       program_invocation_short_name);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = battery_is_discharging_and_low();
        if (r < 0) {
                log_warning_errno(r, "Failed to check battery status, ignoring: %m");
                return 0;
        }
        if (r > 0) {
                log_emergency("Battery level critically low. Powering off in 10s.");
                sleep(10);
        }

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
