/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "systemctl-compat-runlevel.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "utmp-wtmp.h"

static int runlevel_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("runlevel", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n"
               "\n%sPrints the previous and current runlevel of the init system.%s\n"
               "\nOptions:\n"
               "     --help      Show this help\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

int runlevel_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0)
                switch (c) {

                case ARG_HELP:
                        return runlevel_help();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

        return 1;
}

int runlevel_main(void) {
        int r, runlevel, previous;

        r = utmp_get_runlevel(&runlevel, &previous);
        if (r < 0) {
                puts("unknown");
                return r;
        }

        printf("%c %c\n",
               previous <= 0 ? 'N' : previous,
               runlevel <= 0 ? 'N' : runlevel);

        return 0;
}
