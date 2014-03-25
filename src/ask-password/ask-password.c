/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <termios.h>
#include <limits.h>
#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "util.h"
#include "strv.h"
#include "ask-password-api.h"
#include "def.h"

static const char *arg_icon = NULL;
static const char *arg_id = NULL;
static const char *arg_message = NULL;
static bool arg_use_tty = true;
static usec_t arg_timeout = DEFAULT_TIMEOUT_USEC;
static bool arg_accept_cached = false;
static bool arg_multiple = false;

static int help(void) {

        printf("%s [OPTIONS...] MESSAGE\n\n"
               "Query the user for a system passphrase, via the TTY or an UI agent.\n\n"
               "  -h --help          Show this help\n"
               "     --icon=NAME     Icon name\n"
               "     --timeout=SEC   Timeout in sec\n"
               "     --no-tty        Ask question via agent even on TTY\n"
               "     --accept-cached Accept cached passwords\n"
               "     --multiple      List multiple passwords if available\n"
               "     --id=ID         Query identifier (e.g. cryptsetup:/dev/sda5)\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_ICON = 0x100,
                ARG_TIMEOUT,
                ARG_NO_TTY,
                ARG_ACCEPT_CACHED,
                ARG_MULTIPLE,
                ARG_ID
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "icon",          required_argument, NULL, ARG_ICON          },
                { "timeout",       required_argument, NULL, ARG_TIMEOUT       },
                { "no-tty",        no_argument,       NULL, ARG_NO_TTY        },
                { "accept-cached", no_argument,       NULL, ARG_ACCEPT_CACHED },
                { "multiple",      no_argument,       NULL, ARG_MULTIPLE      },
                { "id",            required_argument, NULL, ARG_ID            },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_ICON:
                        arg_icon = optarg;
                        break;

                case ARG_TIMEOUT:
                        if (parse_sec(optarg, &arg_timeout) < 0) {
                                log_error("Failed to parse --timeout parameter %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_TTY:
                        arg_use_tty = false;
                        break;

                case ARG_ACCEPT_CACHED:
                        arg_accept_cached = true;
                        break;

                case ARG_MULTIPLE:
                        arg_multiple = true;
                        break;

                case ARG_ID:
                        arg_id = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind != argc-1) {
                help();
                return -EINVAL;
        }

        arg_message = argv[optind];
        return 1;
}

int main(int argc, char *argv[]) {
        int r;
        usec_t timeout;

        log_parse_environment();
        log_open();

        if ((r = parse_argv(argc, argv)) <= 0)
                goto finish;

        if (arg_timeout > 0)
                timeout = now(CLOCK_MONOTONIC) + arg_timeout;
        else
                timeout = 0;

        if (arg_use_tty && isatty(STDIN_FILENO)) {
                char *password = NULL;

                if ((r = ask_password_tty(arg_message, timeout, NULL, &password)) >= 0) {
                        puts(password);
                        free(password);
                }

        } else {
                char **l;

                if ((r = ask_password_agent(arg_message, arg_icon, arg_id, timeout, arg_accept_cached, &l)) >= 0) {
                        char **p;

                        STRV_FOREACH(p, l) {
                                puts(*p);

                                if (!arg_multiple)
                                        break;
                        }

                        strv_free(l);
                }
        }

finish:

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
