/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-message-util.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("oomctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%2$sManage or inspect the userspace OOM killer.%3$s\n"
               "\n%4$sCommands:%5$s\n"
               "  dump                        Output the current state of systemd-oomd\n"
               "\n%4$sOptions:%5$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "\nSee the %6$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int dump_state(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_oom_mgr, "DumpByFileDescriptor", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump context: %s", bus_error_message(&error, r));

        return bus_message_dump_fd(reply);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",     no_argument, NULL, 'h'          },
                { "version",  no_argument, NULL, ARG_VERSION  },
                { "no-pager", no_argument, NULL, ARG_NO_PAGER },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                        case 'h':
                                return help(0, NULL, NULL);

                        case ARG_VERSION:
                                return version();

                        case ARG_NO_PAGER:
                                arg_pager_flags |= PAGER_DISABLE;
                                break;

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached();
                }

        return 1;
}

static int run(int argc, char* argv[]) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0,            help       },
                { "dump", VERB_ANY, 1,        VERB_DEFAULT, dump_state },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
