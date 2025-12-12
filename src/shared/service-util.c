/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "bus-object.h"
#include "log.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "service-util.h"

typedef enum HelpFlags {
        HELP_WITH_BUS_INTROSPECT = 1 << 0,
        HELP_WITH_RUNTIME_SCOPE  = 1 << 1,
} HelpFlags;

static int help(const char *program_path,
                const char *service,
                const char *description,
                HelpFlags flags) {

        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man(service, "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%5$s%7$s%6$s\n"
               "\nThis program takes no positional arguments.\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "%8$s"
               "%9$s"
               "\nSee the %2$s for details.\n",
               program_path,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal(),
               description,
               FLAGS_SET(flags, HELP_WITH_BUS_INTROSPECT) ? "     --bus-introspect=PATH  Write D-Bus XML introspection data\n" : "",
               FLAGS_SET(flags, HELP_WITH_RUNTIME_SCOPE)  ? "     --system               Start service in system mode\n"
                                                            "     --user                 Start service in user mode\n" : "");

        return 0; /* No further action */
}

int service_parse_argv(
                const char *service,
                const char *description,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_BUS_INTROSPECT,
                ARG_SYSTEM,
                ARG_USER,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                { "bus-introspect", required_argument, NULL, ARG_BUS_INTROSPECT },
                { "system",         no_argument,       NULL, ARG_SYSTEM         },
                { "user",           no_argument,       NULL, ARG_USER           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help(argv[0],
                                    service,
                                    description,
                                    (bus_objects ? HELP_WITH_BUS_INTROSPECT : 0) |
                                    (runtime_scope ? HELP_WITH_RUNTIME_SCOPE : 0));

                case ARG_VERSION:
                        return version();

                case ARG_BUS_INTROSPECT:
                        return bus_introspect_implementations(
                                        stdout,
                                        optarg,
                                        bus_objects);

                case ARG_SYSTEM:
                case ARG_USER:
                        if (!runtime_scope)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This service cannot be run in --system or --user mode, refusing.");

                        *runtime_scope = c == ARG_SYSTEM ? RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        return 1; /* Further action */
}
