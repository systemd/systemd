/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 David Strauss

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

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "log.h"
#include "socket-util.h"
#include "util.h"
#include "event-util.h"
#include "build.h"
#include "set.h"
#include "path-util.h"

#define BUFFER_SIZE (256 * 1024)
#define CONNECTIONS_MAX 256

#define _cleanup_freeaddrinfo_ _cleanup_(freeaddrinfop)
DEFINE_TRIVIAL_CLEANUP_FUNC(struct addrinfo *, freeaddrinfo);

typedef struct Context {
        Set *listen;
        Set *connections;
} Context;

typedef struct Connection {
        Context *context;

        int server_fd, client_fd;
        int server_to_client_buffer[2]; /* a pipe */
        int client_to_server_buffer[2]; /* a pipe */

        size_t server_to_client_buffer_full, client_to_server_buffer_full;
        size_t server_to_client_buffer_size, client_to_server_buffer_size;

        sd_event_source *server_event_source, *client_event_source;
} Connection;

static const char *arg_remote_host = NULL;

static void connection_free(Connection *c) {
        assert(c);

        if (c->context)
                set_remove(c->context->connections, c);

        sd_event_source_unref(c->server_event_source);
        sd_event_source_unref(c->client_event_source);

        safe_close(c->server_fd);
        safe_close(c->client_fd);

        safe_close_pair(c->server_to_client_buffer);
        safe_close_pair(c->client_to_server_buffer);

        free(c);
}

static void context_free(Context *context) {
        sd_event_source *es;
        Connection *c;

        assert(context);

        while ((es = set_steal_first(context->listen)))
                sd_event_source_unref(es);

        while ((c = set_first(context->connections)))
                connection_free(c);

        set_free(context->listen);
        set_free(context->connections);
}

static int get_remote_sockaddr(union sockaddr_union *sa, socklen_t *salen) {
        int r;

        assert(sa);
        assert(salen);

        if (path_is_absolute(arg_remote_host)) {
                sa->un.sun_family = AF_UNIX;
                strncpy(sa->un.sun_path, arg_remote_host, sizeof(sa->un.sun_path)-1);
                sa->un.sun_path[sizeof(sa->un.sun_path)-1] = 0;

                *salen = offsetof(union sockaddr_union, un.sun_path) + strlen(sa->un.sun_path);

        } else if (arg_remote_host[0] == '@') {
                sa->un.sun_family = AF_UNIX;
                sa->un.sun_path[0] = 0;
                strncpy(sa->un.sun_path+1, arg_remote_host+1, sizeof(sa->un.sun_path)-2);
                sa->un.sun_path[sizeof(sa->un.sun_path)-1] = 0;

                *salen = offsetof(union sockaddr_union, un.sun_path) + 1 + strlen(sa->un.sun_path + 1);

        } else {
                _cleanup_freeaddrinfo_ struct addrinfo *result = NULL;
                const char *node, *service;

                struct addrinfo hints = {
                        .ai_family = AF_UNSPEC,
                        .ai_socktype = SOCK_STREAM,
                        .ai_flags = AI_ADDRCONFIG
                };

                service = strrchr(arg_remote_host, ':');
                if (service) {
                        node = strndupa(arg_remote_host, service - arg_remote_host);
                        service ++;
                } else {
                        node = arg_remote_host;
                        service = "80";
                }

                log_debug("Looking up address info for %s:%s", node, service);
                r = getaddrinfo(node, service, &hints, &result);
                if (r != 0) {
                        log_error("Failed to resolve host %s:%s: %s", node, service, gai_strerror(r));
                        return -EHOSTUNREACH;
                }

                assert(result);
                if (result->ai_addrlen > sizeof(union sockaddr_union)) {
                        log_error("Address too long.");
                        return -E2BIG;
                }

                memcpy(sa, result->ai_addr, result->ai_addrlen);
                *salen = result->ai_addrlen;
        }

        return 0;
}

static int connection_create_pipes(Connection *c, int buffer[2], size_t *sz) {
        int r;

        assert(c);
        assert(buffer);
        assert(sz);

        if (buffer[0] >= 0)
                return 0;

        r = pipe2(buffer, O_CLOEXEC|O_NONBLOCK);
        if (r < 0) {
                log_error("Failed to allocate pipe buffer: %m");
                return -errno;
        }

        fcntl(buffer[0], F_SETPIPE_SZ, BUFFER_SIZE);

        r = fcntl(buffer[0], F_GETPIPE_SZ);
        if (r < 0) {
                log_error("Failed to get pipe buffer size: %m");
                return -errno;
        }

        assert(r > 0);
        *sz = r;

        return 0;
}

static int connection_shovel(
                Connection *c,
                int *from, int buffer[2], int *to,
                size_t *full, size_t *sz,
                sd_event_source **from_source, sd_event_source **to_source) {

        bool shoveled;

        assert(c);
        assert(from);
        assert(buffer);
        assert(buffer[0] >= 0);
        assert(buffer[1] >= 0);
        assert(to);
        assert(full);
        assert(sz);
        assert(from_source);
        assert(to_source);

        do {
                ssize_t z;

                shoveled = false;

                if (*full < *sz && *from >= 0 && *to >= 0) {
                        z = splice(*from, NULL, buffer[1], NULL, *sz - *full, SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
                        if (z > 0) {
                                *full += z;
                                shoveled = true;
                        } else if (z == 0 || errno == EPIPE || errno == ECONNRESET) {
                                *from_source = sd_event_source_unref(*from_source);
                                *from = safe_close(*from);
                        } else if (errno != EAGAIN && errno != EINTR) {
                                log_error("Failed to splice: %m");
                                return -errno;
                        }
                }

                if (*full > 0 && *to >= 0) {
                        z = splice(buffer[0], NULL, *to, NULL, *full, SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
                        if (z > 0) {
                                *full -= z;
                                shoveled = true;
                        } else if (z == 0 || errno == EPIPE || errno == ECONNRESET) {
                                *to_source = sd_event_source_unref(*to_source);
                                *to = safe_close(*to);
                        } else if (errno != EAGAIN && errno != EINTR) {
                                log_error("Failed to splice: %m");
                                return -errno;
                        }
                }
        } while (shoveled);

        return 0;
}

static int connection_enable_event_sources(Connection *c, sd_event *event);

static int traffic_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Connection *c = userdata;
        int r;

        assert(s);
        assert(fd >= 0);
        assert(c);

        r = connection_shovel(c,
                              &c->server_fd, c->server_to_client_buffer, &c->client_fd,
                              &c->server_to_client_buffer_full, &c->server_to_client_buffer_size,
                              &c->server_event_source, &c->client_event_source);
        if (r < 0)
                goto quit;

        r = connection_shovel(c,
                              &c->client_fd, c->client_to_server_buffer, &c->server_fd,
                              &c->client_to_server_buffer_full, &c->client_to_server_buffer_size,
                              &c->client_event_source, &c->server_event_source);
        if (r < 0)
                goto quit;

        /* EOF on both sides? */
        if (c->server_fd == -1 && c->client_fd == -1)
                goto quit;

        /* Server closed, and all data written to client? */
        if (c->server_fd == -1 && c->server_to_client_buffer_full <= 0)
                goto quit;

        /* Client closed, and all data written to server? */
        if (c->client_fd == -1 && c->client_to_server_buffer_full <= 0)
                goto quit;

        r = connection_enable_event_sources(c, sd_event_source_get_event(s));
        if (r < 0)
                goto quit;

        return 1;

quit:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int connection_enable_event_sources(Connection *c, sd_event *event) {
        uint32_t a = 0, b = 0;
        int r;

        assert(c);
        assert(event);

        if (c->server_to_client_buffer_full > 0)
                b |= EPOLLOUT;
        if (c->server_to_client_buffer_full < c->server_to_client_buffer_size)
                a |= EPOLLIN;

        if (c->client_to_server_buffer_full > 0)
                a |= EPOLLOUT;
        if (c->client_to_server_buffer_full < c->client_to_server_buffer_size)
                b |= EPOLLIN;

        if (c->server_event_source)
                r = sd_event_source_set_io_events(c->server_event_source, a);
        else if (c->server_fd >= 0)
                r = sd_event_add_io(event, &c->server_event_source, c->server_fd, a, traffic_cb, c);
        else
                r = 0;

        if (r < 0) {
                log_error("Failed to set up server event source: %s", strerror(-r));
                return r;
        }

        if (c->client_event_source)
                r = sd_event_source_set_io_events(c->client_event_source, b);
        else if (c->client_fd >= 0)
                r = sd_event_add_io(event, &c->client_event_source, c->client_fd, b, traffic_cb, c);
        else
                r = 0;

        if (r < 0) {
                log_error("Failed to set up client event source: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int connect_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Connection *c = userdata;
        socklen_t solen;
        int error, r;

        assert(s);
        assert(fd >= 0);
        assert(c);

        solen = sizeof(error);
        r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &solen);
        if (r < 0) {
                log_error("Failed to issue SO_ERROR: %m");
                goto fail;
        }

        if (error != 0) {
                log_error("Failed to connect to remote host: %s", strerror(error));
                goto fail;
        }

        c->client_event_source = sd_event_source_unref(c->client_event_source);

        r = connection_create_pipes(c, c->server_to_client_buffer, &c->server_to_client_buffer_size);
        if (r < 0)
                goto fail;

        r = connection_create_pipes(c, c->client_to_server_buffer, &c->client_to_server_buffer_size);
        if (r < 0)
                goto fail;

        r = connection_enable_event_sources(c, sd_event_source_get_event(s));
        if (r < 0)
                goto fail;

        return 0;

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int add_connection_socket(Context *context, sd_event *event, int fd) {
        union sockaddr_union sa = {};
        socklen_t salen;
        Connection *c;
        int r;

        assert(context);
        assert(event);
        assert(fd >= 0);

        if (set_size(context->connections) > CONNECTIONS_MAX) {
                log_warning("Hit connection limit, refusing connection.");
                safe_close(fd);
                return 0;
        }

        r = set_ensure_allocated(&context->connections, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return log_oom();

        c = new0(Connection, 1);
        if (!c)
                return log_oom();

        c->context = context;
        c->server_fd = fd;
        c->client_fd = -1;
        c->server_to_client_buffer[0] = c->server_to_client_buffer[1] = -1;
        c->client_to_server_buffer[0] = c->client_to_server_buffer[1] = -1;

        r = set_put(context->connections, c);
        if (r < 0) {
                free(c);
                return log_oom();
        }

        r = get_remote_sockaddr(&sa, &salen);
        if (r < 0)
                goto fail;

        c->client_fd = socket(sa.sa.sa_family, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (c->client_fd < 0) {
                log_error("Failed to get remote socket: %m");
                goto fail;
        }

        r = connect(c->client_fd, &sa.sa, salen);
        if (r < 0) {
                if (errno == EINPROGRESS) {
                        r = sd_event_add_io(event, &c->client_event_source, c->client_fd, EPOLLOUT, connect_cb, c);
                        if (r < 0) {
                                log_error("Failed to add connection socket: %s", strerror(-r));
                                goto fail;
                        }

                        r = sd_event_source_set_enabled(c->client_event_source, SD_EVENT_ONESHOT);
                        if (r < 0) {
                                log_error("Failed to enable oneshot event source: %s", strerror(-r));
                                goto fail;
                        }
                } else {
                        log_error("Failed to connect to remote host: %m");
                        goto fail;
                }
        } else {
                r = connection_enable_event_sources(c, event);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        connection_free(c);
        return 0; /* ignore non-OOM errors, continue serving */
}

static int accept_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ char *peer = NULL;
        Context *context = userdata;
        int nfd = -1, r;

        assert(s);
        assert(fd >= 0);
        assert(revents & EPOLLIN);
        assert(context);

        nfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (nfd < 0) {
                if (errno != -EAGAIN)
                        log_warning("Failed to accept() socket: %m");
        } else {
                getpeername_pretty(nfd, &peer);
                log_debug("New connection from %s", strna(peer));

                r = add_connection_socket(context, sd_event_source_get_event(s), nfd);
                if (r < 0) {
                        log_error("Failed to accept connection, ignoring: %s", strerror(-r));
                        safe_close(fd);
                }
        }

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_error("Error while re-enabling listener with ONESHOT: %s", strerror(-r));
                sd_event_exit(sd_event_source_get_event(s), r);
                return r;
        }

        return 1;
}

static int add_listen_socket(Context *context, sd_event *event, int fd) {
        sd_event_source *source;
        int r;

        assert(context);
        assert(event);
        assert(fd >= 0);

        r = set_ensure_allocated(&context->listen, trivial_hash_func, trivial_compare_func);
        if (r < 0) {
                log_oom();
                return r;
        }

        r = sd_is_socket(fd, 0, SOCK_STREAM, 1);
        if (r < 0) {
                log_error("Failed to determine socket type: %s", strerror(-r));
                return r;
        }
        if (r == 0) {
                log_error("Passed in socket is not a stream socket.");
                return -EINVAL;
        }

        r = fd_nonblock(fd, true);
        if (r < 0) {
                log_error("Failed to mark file descriptor non-blocking: %s", strerror(-r));
                return r;
        }

        r = sd_event_add_io(event, &source, fd, EPOLLIN, accept_cb, context);
        if (r < 0) {
                log_error("Failed to add event source: %s", strerror(-r));
                return r;
        }

        r = set_put(context->listen, source);
        if (r < 0) {
                log_error("Failed to add source to set: %s", strerror(-r));
                sd_event_source_unref(source);
                return r;
        }

        /* Set the watcher to oneshot in case other processes are also
         * watching to accept(). */
        r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_error("Failed to enable oneshot mode: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int help(void) {

        printf("%s [HOST:PORT]\n"
               "%s [SOCKET]\n\n"
               "Bidirectionally proxy local sockets to another (possibly remote) socket.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n",
               program_invocation_short_name,
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_IGNORE_ENV
        };

        static const struct option options[] = {
                { "help",       no_argument, NULL, 'h'           },
                { "version",    no_argument, NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind >= argc) {
                log_error("Not enough parameters.");
                return -EINVAL;
        }

        if (argc != optind+1) {
                log_error("Too many parameters.");
                return -EINVAL;
        }

        arg_remote_host = argv[optind];
        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *event = NULL;
        Context context = {};
        int r, n, fd;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_event_default(&event);
        if (r < 0) {
                log_error("Failed to allocate event loop: %s", strerror(-r));
                goto finish;
        }

        sd_event_set_watchdog(event, true);

        n = sd_listen_fds(1);
        if (n < 0) {
                log_error("Failed to receive sockets from parent.");
                r = n;
                goto finish;
        } else if (n == 0) {
                log_error("Didn't get any sockets passed in.");
                r = -EINVAL;
                goto finish;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                r = add_listen_socket(&context, event, fd);
                if (r < 0)
                        goto finish;
        }

        r = sd_event_loop(event);
        if (r < 0) {
                log_error("Failed to run event loop: %s", strerror(-r));
                goto finish;
        }

finish:
        context_free(&context);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
