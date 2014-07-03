/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include "sd-id128.h"
#include "sd-messages.h"
#include "log.h"
#include "util.h"
#include "strv.h"
#include "fileio.h"
#include "build.h"
#include "sleep-config.h"
#include "def.h"

static char* arg_verb = NULL;

static int write_mode(char **modes) {
        int r = 0;
        char **mode;

        STRV_FOREACH(mode, modes) {
                int k;

                k = write_string_file("/sys/power/disk", *mode);
                if (k == 0)
                        return 0;

                log_debug("Failed to write '%s' to /sys/power/disk: %s",
                          *mode, strerror(-k));
                if (r == 0)
                        r = k;
        }

        if (r < 0)
                log_error("Failed to write mode to /sys/power/disk: %s",
                          strerror(-r));

        return r;
}

static int write_state(FILE **f, char **states) {
        char **state;
        int r = 0;

        STRV_FOREACH(state, states) {
                int k;

                k = write_string_stream(*f, *state);
                if (k == 0)
                        return 0;
                log_debug("Failed to write '%s' to /sys/power/state: %s",
                          *state, strerror(-k));
                if (r == 0)
                        r = k;

                fclose(*f);
                *f = fopen("/sys/power/state", "we");
                if (!*f) {
                        log_error("Failed to open /sys/power/state: %m");
                        return -errno;
                }
        }

        return r;
}

static int execute(char **modes, char **states) {
        char* arguments[4];
        int r;
        _cleanup_fclose_ FILE *f = NULL;
        const char* note = strappenda("SLEEP=", arg_verb);

        /* This file is opened first, so that if we hit an error,
         * we can abort before modifying any state. */
        f = fopen("/sys/power/state", "we");
        if (!f) {
                log_error("Failed to open /sys/power/state: %m");
                return -errno;
        }

        /* Configure the hibernation mode */
        r = write_mode(modes);
        if (r < 0)
                return r;

        arguments[0] = NULL;
        arguments[1] = (char*) "pre";
        arguments[2] = arg_verb;
        arguments[3] = NULL;
        execute_directory(SYSTEM_SLEEP_PATH, NULL, DEFAULT_TIMEOUT_USEC, arguments);

        log_struct(LOG_INFO,
                   MESSAGE_ID(SD_MESSAGE_SLEEP_START),
                   "MESSAGE=Suspending system...",
                   note,
                   NULL);

        r = write_state(&f, states);
        if (r < 0)
                return r;

        log_struct(LOG_INFO,
                   MESSAGE_ID(SD_MESSAGE_SLEEP_STOP),
                   "MESSAGE=System resumed.",
                   note,
                   NULL);

        arguments[1] = (char*) "post";
        execute_directory(SYSTEM_SLEEP_PATH, NULL, DEFAULT_TIMEOUT_USEC, arguments);

        return r;
}

static int help(void) {

        printf("%s COMMAND\n\n"
               "Suspend the system, hibernate the system, or both.\n\n"
               "Commands:\n"
               "  -h --help            Show this help and exit\n"
               "  --version            Print version string and exit\n"
               "  suspend              Suspend the system\n"
               "  hibernate            Hibernate the system\n"
               "  hybrid-sleep         Both hibernate and suspend the system\n"
               , program_invocation_short_name
               );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version",      no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+h", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc - optind != 1) {
                log_error("Usage: %s COMMAND",
                          program_invocation_short_name);
                return -EINVAL;
        }

        arg_verb = argv[optind];

        if (!streq(arg_verb, "suspend") &&
            !streq(arg_verb, "hibernate") &&
            !streq(arg_verb, "hybrid-sleep")) {
                log_error("Unknown command '%s'.", arg_verb);
                return -EINVAL;
        }

        return 1 /* work to do */;
}

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = parse_sleep_config(arg_verb, &modes, &states);
        if (r < 0)
                goto finish;

        r = execute(modes, states);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
