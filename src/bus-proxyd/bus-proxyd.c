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
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <stddef.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "build.h"
#include "strv.h"

#define UNIX_BUS_PATH "unix:path=/run/dbus/system_bus_socket"
#define KERNEL_BUS_PATH "kernel:path=/dev/kdbus/0-system/bus"

#ifdef ENABLE_KDBUS
#  define DEFAULT_BUS_PATH KERNEL_BUS_PATH ";" UNIX_BUS_PATH
#else
#  define DEFAULT_BUS_PATH UNIX_BUS_PATH
#endif

static const char *arg_address = DEFAULT_BUS_PATH;
static char *arg_command_line_buffer = NULL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Connect STDIO or a socket to a given bus address.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --address=ADDRESS   Connect to the bus specified by ADDRESS\n"
               "                         (default: " DEFAULT_BUS_PATH ")\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ADDRESS,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "address",    required_argument, NULL, ARG_ADDRESS    },
                { NULL,         0,                 NULL, 0              }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hsup:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_ADDRESS:
                        arg_address = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        /* If the first command line argument is only "x" characters
         * we'll write who we are talking to into it, so that "ps" is
         * explanatory */
        arg_command_line_buffer = argv[optind];
        if (argc > optind + 1 ||
            (arg_command_line_buffer && arg_command_line_buffer[strspn(arg_command_line_buffer, "x")] != 0)) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        _cleanup_bus_unref_ sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        int r, in_fd, out_fd;
        char **cmdline;
        const char *comm;
        bool is_unix;
        uid_t uid;
        pid_t pid;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_listen_fds(0);
        if (r == 0) {
                in_fd = STDIN_FILENO;
                out_fd = STDOUT_FILENO;
        } else if (r == 1) {
                in_fd = SD_LISTEN_FDS_START;
                out_fd = SD_LISTEN_FDS_START;
        } else {
                log_error("Illegal number of file descriptors passed\n");
                goto finish;
        }

        is_unix =
                sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        r = sd_bus_new(&a);
        if (r < 0) {
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_address(a, arg_address);
        if (r < 0) {
                log_error("Failed to set address to connect to: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_negotiate_fds(a, is_unix);
        if (r < 0) {
                log_error("Failed to set FD negotiation: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_start(a);
        if (r < 0) {
                log_error("Failed to start bus client: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_get_server_id(a, &server_id);
        if (r < 0) {
                log_error("Failed to get server ID: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_new(&b);
        if (r < 0) {
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_fd(b, in_fd, out_fd);
        if (r < 0) {
                log_error("Failed to set fds: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_server(b, 1, server_id);
        if (r < 0) {
                log_error("Failed to set server mode: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_negotiate_fds(b, is_unix);
        if (r < 0) {
                log_error("Failed to set FD negotiation: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_anonymous(b, true);
        if (r < 0) {
                log_error("Failed to set anonymous authentication: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_start(b);
        if (r < 0) {
                log_error("Failed to start bus client: %s", strerror(-r));
                goto finish;
        }

        if (sd_bus_get_peer_creds(b, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_COMM, &creds) >= 0 &&
            sd_bus_creds_get_uid(creds, &uid) >= 0 &&
            sd_bus_creds_get_pid(creds, &pid) >= 0 &&
            sd_bus_creds_get_cmdline(creds, &cmdline) >= 0 &&
            sd_bus_creds_get_comm(creds, &comm) >= 0) {
                _cleanup_free_ char *p = NULL, *name = NULL;

                name = uid_to_name(uid);
                if (!name) {
                        r = log_oom();
                        goto finish;
                }

                p = strv_join(cmdline, " ");
                if (!p) {
                        r = log_oom();
                        goto finish;
                }

                /* The status string gets the full command line ... */
                sd_notifyf(false,
                           "STATUS=Processing requests from client PID %lu (%s); UID %lu (%s)",
                           (unsigned long) pid, p,
                           (unsigned long) uid, name);

                /* ... and the argv line only the short comm */
                if (arg_command_line_buffer) {
                        size_t m, w;

                        m = strlen(arg_command_line_buffer);
                        w = snprintf(arg_command_line_buffer, m,
                                     "[PID %lu/%s; UID %lu/%s]",
                                     (unsigned long) pid, comm,
                                     (unsigned long) uid, name);

                        if (m > w)
                                memset(arg_command_line_buffer + w, 0, m - w);

                }
        }

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                uint64_t t;
                struct timespec _ts, *ts;
                struct pollfd *pollfd;
                int k, i, fd;

                struct bus_bus {
                        sd_bus *bus;
                        const char *name;
                        int events;
                        uint64_t timeout;
                } busses[2] = {
                        {a, "a"},
                        {b, "b"},
                };

                for (i = 0; i < 2; i ++) {
                        r = sd_bus_process(busses[i].bus, &m);
                        if (r < 0) {
                                /* treat 'connection reset by peer' as clean exit condition */
                                if (r == -ECONNRESET)
                                        r = 0;
                                else
                                        log_error("Failed to process bus %s: %s",
                                                  busses[i].name, strerror(-r));
                                goto finish;
                        }

                        if (m) {
                                /* We officially got EOF, let's quit */
                                if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected")) {
                                        r = 0;
                                        goto finish;
                                }

                                k = sd_bus_send(busses[1-i].bus, m, NULL);
                                if (k < 0) {
                                        r = k;
                                        log_error("Failed to send message to bus %s: %s",
                                                  busses[1-i].name, strerror(-r));
                                        goto finish;
                                }
                        }

                        if (r > 0)
                                continue;
                }

                fd = sd_bus_get_fd(a);
                if (fd < 0) {
                        log_error("Failed to get fd: %s", strerror(-r));
                        goto finish;
                }

                for (i = 0; i < 2; i ++) {
                        busses[i].events = sd_bus_get_events(a);
                        if (busses[i].events < 0) {
                                log_error("Failed to get events mask: %s", strerror(-r));
                                goto finish;
                        }

                        r = sd_bus_get_timeout(a, &busses[i].timeout);
                        if (r < 0) {
                                log_error("Failed to get timeout: %s", strerror(-r));
                                goto finish;
                        }
                }

                t = busses[0].timeout;
                if (t == (uint64_t) -1 ||
                    (busses[1].timeout != (uint64_t) -1 && busses[1].timeout < t))
                        t = busses[1].timeout;

                if (t == (uint64_t) -1)
                        ts = NULL;
                else {
                        usec_t nw;

                        nw = now(CLOCK_MONOTONIC);
                        if (t > nw)
                                t -= nw;
                        else
                                t = 0;

                        ts = timespec_store(&_ts, t);
                }

                pollfd = (struct pollfd[3]) {
                        {.fd = fd,     .events = busses[0].events           },
                        {.fd = in_fd,  .events = busses[1].events & POLLIN  },
                        {.fd = out_fd, .events = busses[1].events & POLLOUT },
                };

                r = ppoll(pollfd, 3, ts, NULL);
                if (r < 0) {
                        log_error("ppoll() failed: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        sd_bus_flush(a);
        sd_bus_flush(b);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
