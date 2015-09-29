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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "env-util.h"
#include "formats-util.h"
#include "log.h"
#include "strv.h"
#include "util.h"

static bool arg_ready = false;
static pid_t arg_pid = 0;
static const char *arg_status = NULL;
static bool arg_booted = false;

static void help(void) {
        printf("%s [OPTIONS...] [VARIABLE=VALUE...]\n\n"
               "Notify the init system about service status updates.\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --ready           Inform the init system about service start-up completion\n"
               "     --pid[=PID]       Set main pid of daemon\n"
               "     --status=TEXT     Set status text\n"
               "     --booted          Check if the system was booted up with systemd\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_READY = 0x100,
                ARG_VERSION,
                ARG_PID,
                ARG_STATUS,
                ARG_BOOTED,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "ready",     no_argument,       NULL, ARG_READY     },
                { "pid",       optional_argument, NULL, ARG_PID       },
                { "status",    required_argument, NULL, ARG_STATUS    },
                { "booted",    no_argument,       NULL, ARG_BOOTED    },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_READY:
                        arg_ready = true;
                        break;

                case ARG_PID:

                        if (optarg) {
                                if (parse_pid(optarg, &arg_pid) < 0) {
                                        log_error("Failed to parse PID %s.", optarg);
                                        return -EINVAL;
                                }
                        } else
                                arg_pid = getppid();

                        break;

                case ARG_STATUS:
                        arg_status = optarg;
                        break;

                case ARG_BOOTED:
                        arg_booted = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind >= argc &&
            !arg_ready &&
            !arg_status &&
            !arg_pid &&
            !arg_booted) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char* argv[]) {
        _cleanup_free_ char *status = NULL, *cpid = NULL, *n = NULL;
        _cleanup_strv_free_ char **final_env = NULL;
        char* our_env[4];
        unsigned i = 0;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_booted)
                return sd_booted() <= 0;

        if (arg_ready)
                our_env[i++] = (char*) "READY=1";

        if (arg_status) {
                status = strappend("STATUS=", arg_status);
                if (!status) {
                        r = log_oom();
                        goto finish;
                }

                our_env[i++] = status;
        }

        if (arg_pid > 0) {
                if (asprintf(&cpid, "MAINPID="PID_FMT, arg_pid) < 0) {
                        r = log_oom();
                        goto finish;
                }

                our_env[i++] = cpid;
        }

        our_env[i++] = NULL;

        final_env = strv_env_merge(2, our_env, argv + optind);
        if (!final_env) {
                r = log_oom();
                goto finish;
        }

        if (strv_length(final_env) <= 0) {
                r = 0;
                goto finish;
        }

        n = strv_join(final_env, "\n");
        if (!n) {
                r = log_oom();
                goto finish;
        }

        r = sd_pid_notify(arg_pid ? arg_pid : getppid(), false, n);
        if (r < 0) {
                log_error_errno(r, "Failed to notify init system: %m");
                goto finish;
        } else if (r == 0) {
                log_error("No status data could be sent: $NOTIFY_SOCKET was not set");
                r = -EOPNOTSUPP;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
