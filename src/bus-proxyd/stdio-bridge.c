/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers

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
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "def.h"
#include "formats-util.h"
#include "log.h"
#include "proxy.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static char *arg_address = NULL;
static char *arg_command_line_buffer = NULL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Connect STDIO to a given bus address.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --machine=MACHINE    Connect to specified machine\n"
               "     --address=ADDRESS    Connect to the bus specified by ADDRESS\n"
               "                          (default: " DEFAULT_SYSTEM_BUS_ADDRESS ")\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ADDRESS,
                ARG_MACHINE,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "address",         required_argument, NULL, ARG_ADDRESS         },
                { "machine",         required_argument, NULL, ARG_MACHINE         },
                {},
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_ADDRESS: {
                        char *a;

                        a = strdup(optarg);
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;
                        break;
                }

                case ARG_MACHINE: {
                        _cleanup_free_ char *e = NULL;
                        char *a;

                        e = bus_address_escape(optarg);
                        if (!e)
                                return log_oom();

                        a = strjoin("x-machine-kernel:machine=", e, ";x-machine-unix:machine=", e, NULL);
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        /* If the first command line argument is only "x" characters
         * we'll write who we are talking to into it, so that "ps" is
         * explanatory */
        arg_command_line_buffer = argv[optind];
        if (argc > optind + 1 || (arg_command_line_buffer && !in_charset(arg_command_line_buffer, "x"))) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        if (!arg_address) {
                arg_address = strdup(DEFAULT_SYSTEM_BUS_ADDRESS);
                if (!arg_address)
                        return log_oom();
        }

        return 1;
}

static int rename_service(sd_bus *a, sd_bus *b) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        _cleanup_free_ char *p = NULL, *name = NULL;
        const char *comm;
        char **cmdline;
        uid_t uid;
        pid_t pid;
        int r;

        assert(a);
        assert(b);

        r = sd_bus_get_owner_creds(b, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_COMM|SD_BUS_CREDS_AUGMENT, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pid(creds, &pid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_cmdline(creds, &cmdline);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_comm(creds, &comm);
        if (r < 0)
                return r;

        name = uid_to_name(uid);
        if (!name)
                return -ENOMEM;

        p = strv_join(cmdline, " ");
        if (!p)
                return -ENOMEM;

        /* The status string gets the full command line ... */
        sd_notifyf(false,
                   "STATUS=Processing requests from client PID "PID_FMT" (%s); UID "UID_FMT" (%s)",
                   pid, p,
                   uid, name);

        /* ... and the argv line only the short comm */
        if (arg_command_line_buffer) {
                size_t m, w;

                m = strlen(arg_command_line_buffer);
                w = snprintf(arg_command_line_buffer, m,
                             "[PID "PID_FMT"/%s; UID "UID_FMT"/%s]",
                             pid, comm,
                             uid, name);

                if (m > w)
                        memzero(arg_command_line_buffer + w, m - w);
        }

        log_debug("Running on behalf of PID "PID_FMT" (%s), UID "UID_FMT" (%s), %s",
                  pid, p,
                  uid, name,
                  a->unique_name);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(proxy_freep) Proxy *p = NULL;
        int r;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = proxy_new(&p, STDIN_FILENO, STDOUT_FILENO, arg_address);
        if (r < 0)
                goto finish;

        r = rename_service(p->destination_bus, p->local_bus);
        if (r < 0)
                log_debug_errno(r, "Failed to rename process: %m");

        r = proxy_run(p);

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down.");

        free(arg_address);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
