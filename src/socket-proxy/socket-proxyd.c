/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-resolve.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "resolve-private.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

#define BUFFER_SIZE (256 * 1024)

static unsigned arg_connections_max = 256;
static const char *arg_remote_host = NULL;

typedef struct Context {
        sd_event *event;
        sd_resolve *resolve;

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

        sd_resolve_query *resolve_query;
} Connection;

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

        sd_resolve_query_unref(c->resolve_query);

        free(c);
}

static void context_clear(Context *context) {
        assert(context);

        set_free_with_destructor(context->listen, sd_event_source_unref);
        set_free_with_destructor(context->connections, connection_free);

        sd_event_unref(context->event);
        sd_resolve_unref(context->resolve);
}

static int connection_create_pipes(Connection *c, int buffer[static 2], size_t *sz) {
        int r;

        assert(c);
        assert(buffer);
        assert(sz);

        if (buffer[0] >= 0)
                return 0;

        r = pipe2(buffer, O_CLOEXEC|O_NONBLOCK);
        if (r < 0)
                return log_error_errno(errno, "Failed to allocate pipe buffer: %m");

        (void) fcntl(buffer[0], F_SETPIPE_SZ, BUFFER_SIZE);

        r = fcntl(buffer[0], F_GETPIPE_SZ);
        if (r < 0)
                return log_error_errno(errno, "Failed to get pipe buffer size: %m");

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
                        } else if (z == 0 || ERRNO_IS_DISCONNECT(errno)) {
                                *from_source = sd_event_source_unref(*from_source);
                                *from = safe_close(*from);
                        } else if (!IN_SET(errno, EAGAIN, EINTR))
                                return log_error_errno(errno, "Failed to splice: %m");
                }

                if (*full > 0 && *to >= 0) {
                        z = splice(buffer[0], NULL, *to, NULL, *full, SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
                        if (z > 0) {
                                *full -= z;
                                shoveled = true;
                        } else if (z == 0 || ERRNO_IS_DISCONNECT(errno)) {
                                *to_source = sd_event_source_unref(*to_source);
                                *to = safe_close(*to);
                        } else if (!IN_SET(errno, EAGAIN, EINTR))
                                return log_error_errno(errno, "Failed to splice: %m");
                }
        } while (shoveled);

        return 0;
}

static int connection_enable_event_sources(Connection *c);

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

        r = connection_enable_event_sources(c);
        if (r < 0)
                goto quit;

        return 1;

quit:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int connection_enable_event_sources(Connection *c) {
        uint32_t a = 0, b = 0;
        int r;

        assert(c);

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
                r = sd_event_add_io(c->context->event, &c->server_event_source, c->server_fd, a, traffic_cb, c);
        else
                r = 0;

        if (r < 0)
                return log_error_errno(r, "Failed to set up server event source: %m");

        if (c->client_event_source)
                r = sd_event_source_set_io_events(c->client_event_source, b);
        else if (c->client_fd >= 0)
                r = sd_event_add_io(c->context->event, &c->client_event_source, c->client_fd, b, traffic_cb, c);
        else
                r = 0;

        if (r < 0)
                return log_error_errno(r, "Failed to set up client event source: %m");

        return 0;
}

static int connection_complete(Connection *c) {
        int r;

        assert(c);

        r = connection_create_pipes(c, c->server_to_client_buffer, &c->server_to_client_buffer_size);
        if (r < 0)
                goto fail;

        r = connection_create_pipes(c, c->client_to_server_buffer, &c->client_to_server_buffer_size);
        if (r < 0)
                goto fail;

        r = connection_enable_event_sources(c);
        if (r < 0)
                goto fail;

        return 0;

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
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
                log_error_errno(errno, "Failed to issue SO_ERROR: %m");
                goto fail;
        }

        if (error != 0) {
                log_error_errno(error, "Failed to connect to remote host: %m");
                goto fail;
        }

        c->client_event_source = sd_event_source_unref(c->client_event_source);

        return connection_complete(c);

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int connection_start(Connection *c, struct sockaddr *sa, socklen_t salen) {
        int r;

        assert(c);
        assert(sa);
        assert(salen);

        c->client_fd = socket(sa->sa_family, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (c->client_fd < 0) {
                log_error_errno(errno, "Failed to get remote socket: %m");
                goto fail;
        }

        r = connect(c->client_fd, sa, salen);
        if (r < 0) {
                if (errno == EINPROGRESS) {
                        r = sd_event_add_io(c->context->event, &c->client_event_source, c->client_fd, EPOLLOUT, connect_cb, c);
                        if (r < 0) {
                                log_error_errno(r, "Failed to add connection socket: %m");
                                goto fail;
                        }

                        r = sd_event_source_set_enabled(c->client_event_source, SD_EVENT_ONESHOT);
                        if (r < 0) {
                                log_error_errno(r, "Failed to enable oneshot event source: %m");
                                goto fail;
                        }
                } else {
                        log_error_errno(errno, "Failed to connect to remote host: %m");
                        goto fail;
                }
        } else {
                r = connection_complete(c);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int resolve_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, Connection *c) {
        assert(q);
        assert(c);

        if (ret != 0) {
                log_error("Failed to resolve host: %s", gai_strerror(ret));
                goto fail;
        }

        c->resolve_query = sd_resolve_query_unref(c->resolve_query);

        return connection_start(c, ai->ai_addr, ai->ai_addrlen);

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int resolve_remote(Connection *c) {

        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_flags = AI_ADDRCONFIG
        };

        union sockaddr_union sa = {};
        const char *node, *service;
        int r;

        if (IN_SET(arg_remote_host[0], '/', '@')) {
                int salen;

                salen = sockaddr_un_set_path(&sa.un, arg_remote_host);
                if (salen < 0) {
                        log_error_errno(salen, "Specified address doesn't fit in an AF_UNIX address, refusing: %m");
                        goto fail;
                }

                return connection_start(c, &sa.sa, salen);
        }

        service = strrchr(arg_remote_host, ':');
        if (service) {
                node = strndupa(arg_remote_host, service - arg_remote_host);
                service++;
        } else {
                node = arg_remote_host;
                service = "80";
        }

        log_debug("Looking up address info for %s:%s", node, service);
        r = resolve_getaddrinfo(c->context->resolve, &c->resolve_query, node, service, &hints, resolve_handler, NULL, c);
        if (r < 0) {
                log_error_errno(r, "Failed to resolve remote host: %m");
                goto fail;
        }

        return 0;

fail:
        connection_free(c);
        return 0; /* ignore errors, continue serving */
}

static int add_connection_socket(Context *context, int fd) {
        Connection *c;
        int r;

        assert(context);
        assert(fd >= 0);

        if (set_size(context->connections) > arg_connections_max) {
                log_warning("Hit connection limit, refusing connection.");
                safe_close(fd);
                return 0;
        }

        r = set_ensure_allocated(&context->connections, NULL);
        if (r < 0) {
                log_oom();
                return 0;
        }

        c = new0(Connection, 1);
        if (!c) {
                log_oom();
                return 0;
        }

        c->context = context;
        c->server_fd = fd;
        c->client_fd = -1;
        c->server_to_client_buffer[0] = c->server_to_client_buffer[1] = -1;
        c->client_to_server_buffer[0] = c->client_to_server_buffer[1] = -1;

        r = set_put(context->connections, c);
        if (r < 0) {
                free(c);
                log_oom();
                return 0;
        }

        return resolve_remote(c);
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
                if (!ERRNO_IS_ACCEPT_AGAIN(errno))
                        log_warning_errno(errno, "Failed to accept() socket: %m");
        } else {
                (void) getpeername_pretty(nfd, true, &peer);
                log_debug("New connection from %s", strna(peer));

                r = add_connection_socket(context, nfd);
                if (r < 0) {
                        log_error_errno(r, "Failed to accept connection, ignoring: %m");
                        safe_close(fd);
                }
        }

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_error_errno(r, "Error while re-enabling listener with ONESHOT: %m");
                sd_event_exit(context->event, r);
                return r;
        }

        return 1;
}

static int add_listen_socket(Context *context, int fd) {
        sd_event_source *source;
        int r;

        assert(context);
        assert(fd >= 0);

        r = set_ensure_allocated(&context->listen, NULL);
        if (r < 0) {
                log_oom();
                return r;
        }

        r = sd_is_socket(fd, 0, SOCK_STREAM, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket type: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Passed in socket is not a stream socket.");

        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_error_errno(r, "Failed to mark file descriptor non-blocking: %m");

        r = sd_event_add_io(context->event, &source, fd, EPOLLIN, accept_cb, context);
        if (r < 0)
                return log_error_errno(r, "Failed to add event source: %m");

        r = set_put(context->listen, source);
        if (r < 0) {
                log_error_errno(r, "Failed to add source to set: %m");
                sd_event_source_unref(source);
                return r;
        }

        /* Set the watcher to oneshot in case other processes are also
         * watching to accept(). */
        r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to enable oneshot mode: %m");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-socket-proxyd", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [HOST:PORT]\n"
               "%1$s [SOCKET]\n\n"
               "Bidirectionally proxy local sockets to another (possibly remote) socket.\n\n"
               "  -c --connections-max=  Set the maximum number of connections to be accepted\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_IGNORE_ENV
        };

        static const struct option options[] = {
                { "connections-max", required_argument, NULL, 'c'           },
                { "help",            no_argument,       NULL, 'h'           },
                { "version",         no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "c:h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'c':
                        r = safe_atou(optarg, &arg_connections_max);
                        if (r < 0) {
                                log_error("Failed to parse --connections-max= argument: %s", optarg);
                                return r;
                        }

                        if (arg_connections_max < 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Connection limit is too low.");

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough parameters.");

        if (argc != optind+1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many parameters.");

        arg_remote_host = argv[optind];
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context context = {};
        int r, n, fd;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_event_default(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_resolve_default(&context.resolve);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate resolver: %m");

        r = sd_resolve_attach_event(context.resolve, context.event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach resolver: %m");

        sd_event_set_watchdog(context.event, true);

        r = sd_listen_fds(1);
        if (r < 0)
                return log_error_errno(r, "Failed to receive sockets from parent.");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Didn't get any sockets passed in.");

        n = r;

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                r = add_listen_socket(&context, fd);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
