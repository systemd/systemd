/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "terminal-util.h"
#include "util.h"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-boot-check-no-failures.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n"
               "\n%sVerify system operational state.%s\n\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PATH = 0x100,
                ARG_VERSION,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
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

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint32_t n;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "NFailedUnits",
                        &error,
                        'u',
                        &n);
        if (r < 0)
                return log_error_errno(r, "Failed to get failed units counter: %s", bus_error_message(&error, r));

        if (n > 0)
                log_notice("Health check: %" PRIu32 " units have failed.", n);
        else
                log_info("Health check: no failed units.");

        return n > 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
