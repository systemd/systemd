/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Intel Corporation.

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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "fd-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "sd-event.h"
#include "sd-daemon.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"

typedef enum packet_receive_status {
        PACKET_RECEIVE_STATUS_UNDEFINED,
        PACKET_RECEIVE_STATUS_TIMEOUT,
        PACKET_RECEIVE_STATUS_SUCCEEDED,
        _PACKET_RECEIVE_STATUS_MAX,
        _PACKET_RECEIVE_STATUS_INVALID = -1,
} PacketReceiveStatus;

const char* packet_receive_status_to_string(PacketReceiveStatus i) _const_;
PacketReceiveStatus packet_receive_status_from_string(const char *s) _pure_;

struct context {
        PacketReceiveStatus ipv6;
        PacketReceiveStatus timeout;
};

static int timeout_handler(sd_event_source *event_source, usec_t usec, void *data) {
        struct context *ctx = data;

        ctx->timeout = PACKET_RECEIVE_STATUS_TIMEOUT;

        sd_event_exit(sd_event_source_get_event(event_source), 0);
        return 0;
}

static int server_handler(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        ssize_t bytes;
        char buf[4096];
        struct context *ctx = data;

        bytes = recv(fd, buf, sizeof(buf), 0);
        if (bytes < 0)
                return log_error_errno(errno, "Error receiving packet (fd: %d): %m", fd);

        ctx->ipv6 = PACKET_RECEIVE_STATUS_SUCCEEDED;
        sd_event_exit(sd_event_source_get_event(event_source), 0);

        return 0;
}


static void usage(const char *program_name) {
        log_error(
                "Usage: %s <port> <timeout> <%s|%s> <path_to_udp6>\n",
                program_name,
                packet_receive_status_to_string(PACKET_RECEIVE_STATUS_SUCCEEDED),
                packet_receive_status_to_string(PACKET_RECEIVE_STATUS_TIMEOUT));
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_server = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_timeout = NULL;
        int r, reuseaddr = 1;
        _cleanup_close_ int listen_fd_6 = -1;
        struct sockaddr_in6 serv_addr_6 = {};
        PacketReceiveStatus desired;
        usec_t usec;
        uint16_t port;
        usec_t timeout = 0;
        struct context ctx = { PACKET_RECEIVE_STATUS_UNDEFINED };
        char *udp6_path, port_buf[6];
        pid_t udp6_pid;

        /*
         * This software is designed to help with BPF firewall testing.
         *
         * Try to receive an UDP packet on an IPv6 port. If the result is the
         * same as the "desired" result (given as a command line parameter),
         * exit with EXIT_SUCCESS. Else if timeout was desired and timeout was
         * also triggered, exit with EXIT_SUCCESS. Otherwise exit with
         * EXIT_FAILURE.
         */

        if (argc != 5) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        desired = packet_receive_status_from_string(argv[3]);
        if (desired < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        r = parse_ip_port(argv[1], &port);
        if (r < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        if (port == 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        r = parse_sec(argv[2], &timeout);
        if (r < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        udp6_path = argv[4];

        r = sd_event_default(&e);
        if (r < 0) {
                log_error_errno(r, "Error initializing default event: %m\n");
                return EXIT_FAILURE;
        }

        /* server socket */

        listen_fd_6 = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listen_fd_6 < 0)
                return EXIT_FAILURE;

        r = setsockopt(listen_fd_6, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
        if (r < 0)
                return EXIT_FAILURE;

        serv_addr_6.sin6_family = AF_INET6;
        serv_addr_6.sin6_port = htobe16(port);
        r = inet_pton(AF_INET6, "::1", &serv_addr_6.sin6_addr);
        if (r < 0)
                return EXIT_FAILURE;

        r = bind(listen_fd_6, (struct sockaddr *) &serv_addr_6, sizeof(serv_addr_6));
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_add_io(e, &event_source_server, listen_fd_6, EPOLLIN, server_handler, &ctx);
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_source_set_enabled(event_source_server, SD_EVENT_ONESHOT);
        if (r < 0)
                return EXIT_FAILURE;

        /* add the timeout */
        usec = now(CLOCK_MONOTONIC) + timeout;
        r = sd_event_add_time(e, &event_source_timeout, CLOCK_MONOTONIC, usec, 0, timeout_handler, &ctx);
        if (r < 0) {
                log_error_errno(r, "Add timeout error: %m");
                return EXIT_FAILURE;
        }

        r = sd_event_source_set_enabled(event_source_timeout, SD_EVENT_ONESHOT);
        if (r < 0)
                return EXIT_FAILURE;

        r = snprintf(port_buf, sizeof(port_buf), "%u", port);
        if (r < 0 || r == sizeof(port_buf)) {
                log_error_errno(errno, "Error creating port string: %m");
                return EXIT_FAILURE;
        }

        /* run the command to send the packet */
        r = safe_fork("(udp6)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &udp6_pid);
        if (r < 0)
                return EXIT_FAILURE;
        if (r == 0) {
                execl(udp6_path, udp6_path, "-d", "::1", "-a", port_buf,
                        "--dst-opt-hdr", "8",   /* destination option header */
                        "--frag-hdr", "128",    /* fragmentation header */
                        "--hbh-opt-hdr", "8",   /* hop-by-hop header */
                        "--dst-opt-u-hdr", "8", /* unfragmentable destination option header */
                        "--data", "'Test\n\r'", NULL);
                log_error_errno(errno, "Failed to execute udp6: %m");
                return EXIT_FAILURE;
        }

        /*
         * Run the event loop -- wait for connections to complete or timeout to
         * trigger.
         */
        r = sd_event_loop(e);
        if (r < 0) {
                log_error_errno(r, "Event loop error: %m");
                return EXIT_FAILURE;
        }

        if (ctx.timeout == desired && ctx.ipv6 == PACKET_RECEIVE_STATUS_UNDEFINED)
                return EXIT_SUCCESS;
        else if (ctx.ipv6 == desired)
                return EXIT_SUCCESS;

        log_error("Desired state didn't match.");
        log_error("\tdesired state: '%s'", packet_receive_status_to_string(desired));
        log_error("\ttimeout state: '%s'", packet_receive_status_to_string(ctx.timeout));
        log_error("\tipv6 state:    '%s'", packet_receive_status_to_string(ctx.ipv6));

        return EXIT_FAILURE;
}

static const char* const packet_receive_status_table[_PACKET_RECEIVE_STATUS_MAX] = {
        [PACKET_RECEIVE_STATUS_UNDEFINED] = "undefined",
        [PACKET_RECEIVE_STATUS_TIMEOUT] = "timeout",
        [PACKET_RECEIVE_STATUS_SUCCEEDED] = "success",
};

DEFINE_STRING_TABLE_LOOKUP(packet_receive_status, PacketReceiveStatus);
