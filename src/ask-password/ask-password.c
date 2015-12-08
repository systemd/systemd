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

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <unistd.h>

#include "ask-password-api.h"
#include "def.h"
#include "log.h"
#include "macro.h"
#include "strv.h"

static const char *arg_icon = NULL;
static const char *arg_id = NULL;
static const char *arg_keyname = NULL;
static char *arg_message = NULL;
static usec_t arg_timeout = DEFAULT_TIMEOUT_USEC;
static bool arg_multiple = false;
static AskPasswordFlags arg_flags = ASK_PASSWORD_PUSH_CACHE;

static void help(void) {
        printf("%s [OPTIONS...] MESSAGE\n\n"
               "Query the user for a system passphrase, via the TTY or an UI agent.\n\n"
               "  -h --help           Show this help\n"
               "     --icon=NAME      Icon name\n"
               "     --id=ID          Query identifier (e.g. \"cryptsetup:/dev/sda5\")\n"
               "     --keyname=NAME   Kernel key name for caching passwords (e.g. \"cryptsetup\")\n"
               "     --timeout=SEC    Timeout in seconds\n"
               "     --echo           Do not mask input (useful for usernames)\n"
               "     --no-tty         Ask question via agent even on TTY\n"
               "     --accept-cached  Accept cached passwords\n"
               "     --multiple       List multiple passwords if available\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_ICON = 0x100,
                ARG_TIMEOUT,
                ARG_ECHO,
                ARG_NO_TTY,
                ARG_ACCEPT_CACHED,
                ARG_MULTIPLE,
                ARG_ID,
                ARG_KEYNAME,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "icon",          required_argument, NULL, ARG_ICON          },
                { "timeout",       required_argument, NULL, ARG_TIMEOUT       },
                { "echo",          no_argument,       NULL, ARG_ECHO          },
                { "no-tty",        no_argument,       NULL, ARG_NO_TTY        },
                { "accept-cached", no_argument,       NULL, ARG_ACCEPT_CACHED },
                { "multiple",      no_argument,       NULL, ARG_MULTIPLE      },
                { "id",            required_argument, NULL, ARG_ID            },
                { "keyname",       required_argument, NULL, ARG_KEYNAME       },
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

                case ARG_ICON:
                        arg_icon = optarg;
                        break;

                case ARG_TIMEOUT:
                        if (parse_sec(optarg, &arg_timeout) < 0) {
                                log_error("Failed to parse --timeout parameter %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_ECHO:
                        arg_flags |= ASK_PASSWORD_ECHO;
                        break;

                case ARG_NO_TTY:
                        arg_flags |= ASK_PASSWORD_NO_TTY;
                        break;

                case ARG_ACCEPT_CACHED:
                        arg_flags |= ASK_PASSWORD_ACCEPT_CACHED;
                        break;

                case ARG_MULTIPLE:
                        arg_multiple = true;
                        break;

                case ARG_ID:
                        arg_id = optarg;
                        break;

                case ARG_KEYNAME:
                        arg_keyname = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc > optind) {
                arg_message = strv_join(argv + optind, " ");
                if (!arg_message)
                        return log_oom();
        }

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_strv_free_erase_ char **l = NULL;
        usec_t timeout;
        char **p;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_timeout > 0)
                timeout = now(CLOCK_MONOTONIC) + arg_timeout;
        else
                timeout = 0;

        r = ask_password_auto(arg_message, arg_icon, arg_id, arg_keyname, timeout, arg_flags, &l);
        if (r < 0) {
                log_error_errno(r, "Failed to query password: %m");
                goto finish;
        }

        STRV_FOREACH(p, l) {
                puts(*p);

                if (!arg_multiple)
                        break;
        }

finish:
        free(arg_message);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
