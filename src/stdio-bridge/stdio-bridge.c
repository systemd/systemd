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

#include "log.h"
#include "util.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"

int main(int argc, char *argv[]) {
        _cleanup_bus_unref_ sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        bool is_unix;
        int r;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        is_unix =
                sd_is_socket(STDIN_FILENO, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(STDOUT_FILENO, AF_UNIX, 0, 0) > 0;

        r = sd_bus_new(&a);
        if (r < 0) {
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_address(a, "unix:path=/run/dbus/system_bus_socket");
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

        r = sd_bus_set_fd(b, STDIN_FILENO, STDOUT_FILENO);
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

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                int events_a, events_b, fd;
                uint64_t timeout_a, timeout_b, t;
                struct timespec _ts, *ts;

                r = sd_bus_process(a, &m);
                if (r < 0) {
                        log_error("Failed to process bus: %s", strerror(-r));
                        goto finish;
                }

                if (m) {
                        r = sd_bus_send(b, m, NULL);
                        if (r < 0) {
                                log_error("Failed to send message: %s", strerror(-r));
                                goto finish;
                        }
                }

                if (r > 0)
                        continue;

                r = sd_bus_process(b, &m);
                if (r < 0) {
                        log_error("Failed to process bus: %s", strerror(-r));
                        goto finish;
                }

                if (m) {
                        r = sd_bus_send(a, m, NULL);
                        if (r < 0) {
                                log_error("Failed to send message: %s", strerror(-r));
                                goto finish;
                        }
                }

                if (r > 0)
                        continue;

                fd = sd_bus_get_fd(a);
                if (fd < 0) {
                        log_error("Failed to get fd: %s", strerror(-r));
                        goto finish;
                }

                events_a = sd_bus_get_events(a);
                if (events_a < 0) {
                        log_error("Failed to get events mask: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_get_timeout(a, &timeout_a);
                if (r < 0) {
                        log_error("Failed to get timeout: %s", strerror(-r));
                        goto finish;
                }

                events_b = sd_bus_get_events(b);
                if (events_b < 0) {
                        log_error("Failed to get events mask: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_get_timeout(b, &timeout_b);
                if (r < 0) {
                        log_error("Failed to get timeout: %s", strerror(-r));
                        goto finish;
                }

                t = timeout_a;
                if (t == (uint64_t) -1 || (timeout_b != (uint64_t) -1 && timeout_b < timeout_a))
                        t = timeout_b;

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

                {
                        struct pollfd p[3] = {
                                {.fd = fd,            .events = events_a, },
                                {.fd = STDIN_FILENO,  .events = events_b & POLLIN, },
                                {.fd = STDOUT_FILENO, .events = events_b & POLLOUT, }};

                        r = ppoll(p, ELEMENTSOF(p), ts, NULL);
                }
                if (r < 0) {
                        log_error("ppoll() failed: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
