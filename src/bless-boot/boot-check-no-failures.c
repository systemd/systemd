/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pretty-print.h"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-boot-check-no-failures.service", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sVerify system operational state.%s\n\n",
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

        OptionParser opts = { argc, argv };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint32_t n;
        int r;

        log_setup();

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
