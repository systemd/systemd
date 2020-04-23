/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "service-util.h"
#include "terminal-util.h"
#include "util.h"

static int help(const char *program_path, const char *service, const char *description) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man(service, "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "%s%s%s\n\n"
               "This program takes no positional arguments.\n\n"
               "%sOptions%s:\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "\nSee the %s for details.\n"
               , program_path
               , ansi_highlight(), description, ansi_normal()
               , ansi_underline(), ansi_normal()
               , link
        );

        return 0; /* No further action */
}

int service_parse_argv(
                const char *service,
                const char *description,
                int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch(c) {

                case 'h':
                        return help(argv[0], service, description);

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option code.");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        return 1; /* Further action */
}
