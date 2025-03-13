/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "ansi-color.h"
#include "bootspec.h"
#include "find-esp.h"
#include "main-func.h"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-factory-reset-esp.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%5$sDelete non-vendor contents from ESP and XBOOTLDR.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument, NULL, 'h'           },
                { "version",   no_argument, NULL, ARG_VERSION   },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

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
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        FactoryResetMode f = factory_reset_mode();
        if (f < 0)
                return log_error_errno(f, "Failed to determine factory reset mode: %m");
        if (f != FACTORY_RESET_ON)
                return log_error("We are not currently in factory reset mode. Refusing operation.");


        _cleanup_(boot_config_free) BootConfig bc = BOOT_CONFIG_NULL;
        r = boot_config_load_auto(&bc, NULL, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to load boot config: %m");

        // TODO: Walk the ESP and XBOOTLDR, and delete the non-vendor stuff!

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
