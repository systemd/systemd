/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "service-util.h"
#include "terminal-util.h"
#include "util.h"

static int help(const char *program_path, const char *service, const char *description, bool bus_option) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man(service, "8", &link);
        if (r < 0)
                return log_oom();

        static const char *bus_help =
               "     --user                 Run as user service manager\n"
               "     --system               Run as system manager\n";

        printf("%s [OPTIONS...]\n\n"
               "%s%s%s\n\n"
               "This program takes no positional arguments.\n\n"
               "%sOptions%s:\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --bus-introspect=PATH  Write D-Bus XML introspection data\n"
               "%s"
               "\nSee the %s for details.\n"
               , program_path
               , ansi_highlight(), description, ansi_normal()
               , ansi_underline(), ansi_normal()
               , bus_option ? bus_help : ""
               , link
        );

        return 0; /* No further action */
}

int service_parse_argv(
                const char *service,
                const char *description,
                const BusObjectImplementation* const* bus_objects,
                int argc, char *argv[],
                bool *user_bus) {

        enum {
                ARG_VERSION = 0x100,
                ARG_BUS_INTROSPECT,
                ARG_USER,
                ARG_SYSTEM,
        };

        struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                { "bus-introspect", required_argument, NULL, ARG_BUS_INTROSPECT },
                { "user",           no_argument,       NULL, ARG_USER           },
                { "system",         no_argument,       NULL, ARG_SYSTEM         },
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        if (!user_bus)
                options[3].name = NULL;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch(c) {

                case 'h':
                        return help(argv[0], service, description, !!user_bus);

                case ARG_VERSION:
                        return version();

                case ARG_BUS_INTROSPECT:
                        return bus_introspect_implementations(
                                        stdout,
                                        optarg,
                                        bus_objects);
                case ARG_USER:
                        assert(user_bus);
                        *user_bus = true;
                        break;

                case ARG_SYSTEM:
                        assert(user_bus);
                        *user_bus = false;
                        break;

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
