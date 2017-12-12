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
#include "sd-event.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"

typedef enum connection_status {
        CONNECTION_STATUS_UNDEFINED,
        CONNECTION_STATUS_TIMEOUT,
        CONNECTION_STATUS_REFUSED,
        CONNECTION_STATUS_SUCCEEDED,
        _CONNECTION_STATUS_MAX,
        _CONNECTION_STATUS_INVALID = -1,
} ConnectionStatus;

const char* connection_status_to_string(ConnectionStatus i) _const_;
ConnectionStatus connection_status_from_string(const char *s) _pure_;

struct context {
        ConnectionStatus ipv4;
        ConnectionStatus ipv6;
        ConnectionStatus timeout;
};

static int timeout_handler(sd_event_source *event_source, usec_t usec, void *data) {
        struct context *ctx = data;

        ctx->timeout = CONNECTION_STATUS_TIMEOUT;

        sd_event_exit(sd_event_source_get_event(event_source), 0);
        return 0;
}

static int server_handler(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        int conn_fd, r;
        union sockaddr_union addr_name = {};
        socklen_t addr_length = sizeof(addr_name);

        r = getsockname(fd, &addr_name.sa, &addr_length);
        if (r < 0) {
                sd_event_exit(sd_event_source_get_event(event_source), r);
                return -errno;
        }

        if (addr_name.sa.sa_family != AF_INET && addr_name.sa.sa_family != AF_INET6) {
                sd_event_exit(sd_event_source_get_event(event_source), -1);
                return -EAFNOSUPPORT;
        }

        conn_fd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);

        if (conn_fd < 0)
                return log_error_errno(errno, "Error accepting connection (fd: %d): %m", fd);

        return 0;
}

static int server_handler_4(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        return server_handler(event_source, fd, revents, data);
}

static int server_handler_6(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        return server_handler(event_source, fd, revents, data);
}

static int conn_handler(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        int error, r;
        struct context *ctx = data;
        unsigned int length = sizeof(error);
        struct sockaddr addr = { 0 };
        socklen_t addr_length = sizeof(addr);
        ConnectionStatus *status;

        r = getsockname(fd, &addr, &addr_length);
        if (r < 0) {
                sd_event_exit(sd_event_source_get_event(event_source), r);
                return -errno;
        }

        if (addr.sa_family == AF_INET)
                status = &(ctx->ipv4);
        else if (addr.sa_family == AF_INET6)
                status = &(ctx->ipv6);
        else {
                sd_event_exit(sd_event_source_get_event(event_source), -1);
                return -EAFNOSUPPORT;
        }

        r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length);
        if (r < 0) {
                sd_event_exit(sd_event_source_get_event(event_source), r);
                return -errno;
        }

        if (error == 0)
                /* connection succeeded */
                *status = CONNECTION_STATUS_SUCCEEDED;
        else if (error == ECONNREFUSED)
                /* conncetion succeeded but no-one was listening */
                *status = CONNECTION_STATUS_REFUSED;
        else if (error == ETIMEDOUT)
                *status = CONNECTION_STATUS_TIMEOUT;
        else {
                sd_event_exit(sd_event_source_get_event(event_source), -1);
                return -error;
        }

        if (ctx->ipv4 != CONNECTION_STATUS_UNDEFINED && ctx->ipv6 != CONNECTION_STATUS_UNDEFINED)
                sd_event_exit(sd_event_source_get_event(event_source), 0);

        return 0;
}

static int conn_handler_4(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        return conn_handler(event_source, fd, revents, data);
}

static int conn_handler_6(sd_event_source *event_source, int fd, uint32_t revents, void *data) {
        return conn_handler(event_source, fd, revents, data);
}

static void usage(const char *program_name) {
        log_error("Usage: %s <port> <timeout> <%s|%s|%s>",
                program_name,
                connection_status_to_string(CONNECTION_STATUS_SUCCEEDED),
                connection_status_to_string(CONNECTION_STATUS_REFUSED),
                connection_status_to_string(CONNECTION_STATUS_TIMEOUT));
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_conn_4 = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_conn_6 = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_server_4 = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_server_6 = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source_timeout = NULL;
        int r, reuseaddr = 1;
        _cleanup_close_ int fd_4 = -1, fd_6 = -1, listen_fd_4 = -1, listen_fd_6 = -1;
        struct sockaddr_in addr_4 = {}, serv_addr_4 = {};
        struct sockaddr_in6 addr_6 = {}, serv_addr_6 = {};
        ConnectionStatus desired;
        usec_t usec, timeout = 0;
        uint16_t port;
        struct context ctx = { CONNECTION_STATUS_UNDEFINED };

        /*
         * This software is designed to help with BPF firewall testing.
         *
         * Test TCP connection to a localhost port. Try both IPv4 and IPv6
         * address families. If the result for both connections is the same as
         * the "desired" result (given as a command line parameter), exit with
         * EXIT_SUCCESS. Else if timeout was desired and timeout was also
         * triggered, exit with EXIT_SUCCESS. Otherwise exit with EXIT_FAILURE.
         */

        if (argc != 4) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        desired = connection_status_from_string(argv[3]);
        if (desired < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        r = parse_ip_port(argv[1], &port);
        if (r < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        /* we can't allow port 65535, since we are supposed to reply to port+1 */
        if (port == 65535) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        r = parse_sec(argv[2], &timeout);
        if (r < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        r = sd_event_default(&e);
        if (r < 0) {
                log_error_errno(r, "Error initializing default event: %m\n");
                return EXIT_FAILURE;
        }

        /* server sockets */

        listen_fd_4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listen_fd_4 < 0)
                return EXIT_FAILURE;

        r = setsockopt(listen_fd_4, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
        if (r < 0)
                return EXIT_FAILURE;

        /* listen only on loopback interface */

        serv_addr_4.sin_family = AF_INET;
        serv_addr_4.sin_port = htobe16(port);
        r = inet_pton(AF_INET, "127.0.0.1", &serv_addr_4.sin_addr);
        if (r < 0)
                return EXIT_FAILURE;

        r = bind(listen_fd_4, (struct sockaddr *) &serv_addr_4, sizeof(serv_addr_4));
        if (r < 0)
                return EXIT_FAILURE;

        r = listen(listen_fd_4, 1);
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_add_io(e, &event_source_server_4, listen_fd_4, EPOLLIN, server_handler_4, &ctx);
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_source_set_enabled(event_source_server_4, SD_EVENT_ONESHOT);
        if (r < 0)
                return EXIT_FAILURE;

        listen_fd_6 = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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

        r = listen(listen_fd_6, 1);
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_add_io(e, &event_source_server_6, listen_fd_6, EPOLLIN, server_handler_6, &ctx);
        if (r < 0)
                return EXIT_FAILURE;

        r = sd_event_source_set_enabled(event_source_server_6, SD_EVENT_ONESHOT);
        if (r < 0)
                return EXIT_FAILURE;

        /* client sockets */

        fd_4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd_4 < 0)
                return EXIT_FAILURE;

        r = setsockopt(fd_4, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
        if (r < 0)
                return EXIT_FAILURE;

        /* only connect to localhost */

        /*
         * Bind client socket to port+1. This allows for egress testing, because
         * we know which port the server will connect back.
         */

        addr_4.sin_family = AF_INET;
        addr_4.sin_port = htobe16(port+1);
        r = inet_pton(AF_INET, "127.0.0.1", &addr_4.sin_addr);
        if (r < 0)
                return EXIT_FAILURE;

        r = bind(fd_4, (struct sockaddr *) &addr_4, sizeof(addr_4));
        if (r < 0) {
                log_error_errno(r, "IPv4 client bind failed: %m");
                return EXIT_FAILURE;
        }

        addr_4.sin_port = htobe16(port);

        r = connect(fd_4, (struct sockaddr *) &addr_4, sizeof(addr_4));
        if (r == 0)
                ctx.ipv4 = CONNECTION_STATUS_SUCCEEDED;
        else if (r < 0 && errno == EINPROGRESS) {
                r = sd_event_add_io(e, &event_source_conn_4, fd_4, EPOLLOUT, conn_handler_4, &ctx);
                if (r < 0)
                        return EXIT_FAILURE;

                r = sd_event_source_set_enabled(event_source_conn_4, SD_EVENT_ONESHOT);
                if (r < 0)
                        return EXIT_FAILURE;
        } else {
                log_error_errno(r, "IPv4 connection failed: %m");
                return EXIT_FAILURE;
        }

        fd_6 = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd_6 < 0)
                return EXIT_FAILURE;

        r = setsockopt(fd_6, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
        if (r < 0)
                return EXIT_FAILURE;

        addr_6.sin6_family = AF_INET6;
        addr_6.sin6_port = htobe16(port+1);
        r = inet_pton(AF_INET6, "::1", &addr_6.sin6_addr);
        if (r < 0)
                return EXIT_FAILURE;

        r = bind(fd_6, (struct sockaddr *) &addr_6, sizeof(addr_6));
        if (r < 0) {
                log_error_errno(r, "IPv6 client bind failed: %m");
                return EXIT_FAILURE;
        }

        addr_6.sin6_port = htobe16(port);

        r = connect(fd_6, (struct sockaddr *) &addr_6, sizeof(addr_6));
        if (r == 0)
                ctx.ipv6 = CONNECTION_STATUS_SUCCEEDED;
        else if (r < 0 && errno == EINPROGRESS) {
                r = sd_event_add_io(e, &event_source_conn_6, fd_6, EPOLLOUT, conn_handler_6, &ctx);
                if (r < 0)
                        return EXIT_FAILURE;
                r = sd_event_source_set_enabled(event_source_conn_6, SD_EVENT_ONESHOT);
                if (r < 0)
                        return EXIT_FAILURE;
        } else {
                log_error_errno(r, "IPv6 connection failed: %m");
                return EXIT_FAILURE;
        }

        if (ctx.ipv4 != CONNECTION_STATUS_UNDEFINED && ctx.ipv6 != CONNECTION_STATUS_UNDEFINED)
                goto end;

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

        /*
         * Run the event loop -- wait for connections to complete or timeout to
         * trigger.
         */
        r = sd_event_loop(e);
        if (r < 0) {
                log_error_errno(r, "Event loop error: %m");
                return EXIT_FAILURE;
        }

end:
        if (r < 0)
                return EXIT_FAILURE;

        if (ctx.timeout == desired &&
                        ctx.ipv4 == CONNECTION_STATUS_UNDEFINED &&
                        ctx.ipv6 == CONNECTION_STATUS_UNDEFINED)
                return EXIT_SUCCESS;
        else if (ctx.ipv4 == desired && ctx.ipv6 == desired)
                return EXIT_SUCCESS;

        log_error("Desired state didn't match.");
        log_error("\tdesired state: '%s'", connection_status_to_string(desired));
        log_error("\ttimeout state: '%s'", connection_status_to_string(ctx.timeout));
        log_error("\tipv4 state:    '%s'", connection_status_to_string(ctx.ipv4));
        log_error("\tipv6 state:    '%s'", connection_status_to_string(ctx.ipv6));

        return EXIT_FAILURE;
}

static const char* const connection_status_table[_CONNECTION_STATUS_MAX] = {
        [CONNECTION_STATUS_UNDEFINED] = "undefined",
        [CONNECTION_STATUS_TIMEOUT] = "timeout",
        [CONNECTION_STATUS_REFUSED] = "rejected",
        [CONNECTION_STATUS_SUCCEEDED] = "success",
};

DEFINE_STRING_TABLE_LOOKUP(connection_status, ConnectionStatus);
