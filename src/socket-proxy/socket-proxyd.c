/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-resolve.h"

#include "alloc-util.h"
#include "build.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "resolve-private.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

#define BUFFER_SIZE (256 * 1024)

static unsigned arg_connections_max = 256;
static const char *arg_remote_host = NULL;
static usec_t arg_exit_idle_time = USEC_INFINITY;

typedef struct Context {
        sd_event *event;
        sd_resolve *resolve;
        sd_event_source *idle_time;

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

static Connection* connection_free(Connection *c) {
        if (!c)
                return NULL;

        if (c->context)
                set_remove(c->context->connections, c);

        sd_event_source_unref(c->server_event_source);
        sd_event_source_unref(c->client_event_source);

        safe_close(c->server_fd);
        safe_close(c->client_fd);

        safe_close_pair(c->server_to_client_buffer);
        safe_close_pair(c->client_to_server_buffer);

        sd_resolve_query_unref(c->resolve_query);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Connection*, connection_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                connection_hash_ops,
                void, trivial_hash_func, trivial_compare_func,
                Connection, connection_free);

static void context_done(Context *context) {
        assert(context);

        set_free(context->listen);
        set_free(context->connections);

        sd_event_unref(context->event);
        sd_resolve_unref(context->resolve);
        sd_event_source_unref(context->idle_time);
}

static int idle_time_cb(sd_event_source *s, uint64_t usec, void *userdata) {
        Context *c = userdata;
        int r;

        if (!set_isempty(c->connections)) {
                log_warning("Idle timer fired even though there are connections, ignoring");
                return 0;
        }

        r = sd_event_exit(c->event, 0);
        if (r < 0) {
                log_warning_errno(r, "Error while stopping event loop, ignoring: %m");
                return 0;
        }
        return 0;
}

static void context_reset_timer(Context *context) {
        int r;

        assert(context);

        if (arg_exit_idle_time < USEC_INFINITY && set_isempty(context->connections)) {
                r = event_reset_time_relative(
                                context->event, &context->idle_time, CLOCK_MONOTONIC,
                                arg_exit_idle_time, 0, idle_time_cb, context,
                                SD_EVENT_PRIORITY_NORMAL, "idle-timer", /* force_reset = */ true);
                if (r < 0)
                        log_warning_errno(r, "Failed to reset idle timer, ignoring: %m");
        }
}

static void connection_release(Connection *c) {
        Context *context = ASSERT_PTR(ASSERT_PTR(c)->context);

        connection_free(c);
        context_reset_timer(context);
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
                        } else if (!ERRNO_IS_TRANSIENT(errno))
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
                        } else if (!ERRNO_IS_TRANSIENT(errno))
                                return log_error_errno(errno, "Failed to splice: %m");
                }
        } while (shoveled);

        return 0;
}

static int connection_enable_event_sources(Connection *c);

static int traffic_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Connection *c = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

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
        if (c->server_fd < 0 && c->client_fd < 0)
                goto quit;

        /* Server closed, and all data written to client? */
        if (c->server_fd < 0 && c->server_to_client_buffer_full <= 0)
                goto quit;

        /* Client closed, and all data written to server? */
        if (c->client_fd < 0 && c->client_to_server_buffer_full <= 0)
                goto quit;

        r = connection_enable_event_sources(c);
        if (r < 0)
                goto quit;

        return 1;

quit:
        connection_release(c);
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
                return r;

        r = connection_create_pipes(c, c->client_to_server_buffer, &c->client_to_server_buffer_size);
        if (r < 0)
                return r;

        r = connection_enable_event_sources(c);
        if (r < 0)
                return r;

        return 0;
}

static int connect_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Connection *c = ASSERT_PTR(userdata);
        socklen_t solen;
        int error;

        assert(s);
        assert(fd >= 0);

        solen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &solen) < 0) {
                log_error_errno(errno, "Failed to issue SO_ERROR: %m");
                goto fail;
        }

        if (error != 0) {
                log_error_errno(error, "Failed to connect to remote host: %m");
                goto fail;
        }

        c->client_event_source = sd_event_source_unref(c->client_event_source);

        if (connection_complete(c) < 0)
                goto fail;

        return 0;

fail:
        connection_release(c);
        return 0; /* ignore errors, continue serving */
}

static int connection_start(Connection *c, struct sockaddr *sa, socklen_t salen) {
        int r;

        assert(c);
        assert(sa);
        assert(salen);

        c->client_fd = socket(sa->sa_family, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (c->client_fd < 0)
                return log_error_errno(errno, "Failed to get remote socket: %m");

        r = connect(c->client_fd, sa, salen);
        if (r < 0) {
                if (errno != EINPROGRESS)
                        return log_error_errno(errno, "Failed to connect to remote host: %m");

                r = sd_event_add_io(c->context->event, &c->client_event_source, c->client_fd, EPOLLOUT, connect_cb, c);
                if (r < 0)
                        return log_error_errno(r, "Failed to add connection socket: %m");

                r = sd_event_source_set_enabled(c->client_event_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable oneshot event source: %m");

                return 0;
        }

        return connection_complete(c);
}

static int resolve_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, Connection *c) {
        assert(q);
        assert(c);

        if (ret != 0) {
                log_error("Failed to resolve host: %s", gai_strerror(ret));
                goto fail;
        }

        c->resolve_query = sd_resolve_query_unref(c->resolve_query);

        if (connection_start(c, ai->ai_addr, ai->ai_addrlen) < 0)
                goto fail;

        return 0;

fail:
        connection_release(c);
        return 0; /* ignore errors, continue serving */
}

static int resolve_remote(Connection *c) {

        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
        };

        const char *node, *service;
        int r;

        if (IN_SET(arg_remote_host[0], '/', '@')) {
                union sockaddr_union sa;
                int sa_len;

                r = sockaddr_un_set_path(&sa.un, arg_remote_host);
                if (r < 0)
                        return log_error_errno(r, "Specified address doesn't fit in an AF_UNIX address, refusing: %m");
                sa_len = r;

                return connection_start(c, &sa.sa, sa_len);
        }

        service = strrchr(arg_remote_host, ':');
        if (service) {
                node = strndupa_safe(arg_remote_host,
                                     service - arg_remote_host);
                service++;
        } else {
                node = arg_remote_host;
                service = "80";
        }

        log_debug("Looking up address info for %s:%s", node, service);
        r = resolve_getaddrinfo(c->context->resolve, &c->resolve_query, node, service, &hints, resolve_handler, NULL, c);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve remote host: %m");

        return 0;
}

static int context_add_connection(Context *context, int fd) {
        int r;

        assert(context);

        _cleanup_close_ int nfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (nfd < 0) {
                if (!ERRNO_IS_ACCEPT_AGAIN(errno))
                        log_warning_errno(errno, "Failed to accept() socket, ignoring: %m");

                return -errno;
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *peer = NULL;
                (void) getpeername_pretty(nfd, true, &peer);
                log_debug("New connection from %s", strna(peer));
        }

        if (set_size(context->connections) > arg_connections_max)
                return log_warning_errno(SYNTHETIC_ERRNO(EBUSY), "Hit connection limit, refusing connection.");

        r = sd_event_source_set_enabled(context->idle_time, SD_EVENT_OFF);
        if (r < 0)
                log_warning_errno(r, "Unable to disable idle timer, continuing: %m");

        _cleanup_(connection_freep) Connection *c = new(Connection, 1);
        if (!c)
                return log_oom();

        *c = (Connection) {
                .server_fd = TAKE_FD(nfd),
                .client_fd = -EBADF,
                .server_to_client_buffer = EBADF_PAIR,
                .client_to_server_buffer = EBADF_PAIR,
        };

        r = set_ensure_put(&context->connections, &connection_hash_ops, c);
        if (r < 0)
                return log_oom();

        c->context = context;

        r = resolve_remote(c);
        if (r < 0)
                return r;

        TAKE_PTR(c);
        return 0;
}

static int accept_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Context *context = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);
        assert(revents & EPOLLIN);

        if (context_add_connection(context, fd) < 0)
                context_reset_timer(context);

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Error while re-enabling listener with ONESHOT: %m");

        return 1;
}

static int add_listen_socket(Context *context, int fd) {
        int r;

        assert(context);
        assert(fd >= 0);

        r = sd_is_socket(fd, 0, SOCK_STREAM, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket type: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Passed in socket is not a stream socket.");

        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_error_errno(r, "Failed to mark file descriptor non-blocking: %m");

        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        r = sd_event_add_io(context->event, &source, fd, EPOLLIN, accept_cb, context);
        if (r < 0)
                return log_error_errno(r, "Failed to add event source: %m");

        r = sd_event_source_set_exit_on_failure(source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-failure logic: %m");

        /* Set the watcher to oneshot in case other processes are also
         * watching to accept(). */
        r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to enable oneshot mode: %m");

        r = set_ensure_consume(&context->listen, &event_source_hash_ops, TAKE_PTR(source));
        if (r < 0)
                return log_error_errno(r, "Failed to add source to set: %m");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_free_ char *time_link = NULL;
        int r;

        r = terminal_urlify_man("systemd-socket-proxyd", "8", &link);
        if (r < 0)
                return log_oom();
        r = terminal_urlify_man("systemd.time", "7", &time_link);
        if (r < 0)
                return log_oom();

        printf("%1$s [HOST:PORT]\n"
               "%1$s [SOCKET]\n\n"
               "%2$sBidirectionally proxy local sockets to another (possibly remote) socket.%3$s\n\n"
               "  -c --connections-max=  Set the maximum number of connections to be accepted\n"
               "     --exit-idle-time=   Exit when without a connection for this duration. See\n"
               "                         the %4$s for time span format\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "\nSee the %5$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               time_link,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_EXIT_IDLE,
                ARG_IGNORE_ENV
        };

        static const struct option options[] = {
                { "connections-max", required_argument, NULL, 'c'           },
                { "exit-idle-time",  required_argument, NULL, ARG_EXIT_IDLE },
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

                case ARG_EXIT_IDLE:
                        r = parse_sec(optarg, &arg_exit_idle_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --exit-idle-time= argument: %s", optarg);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
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
        _cleanup_(context_done) Context context = {};
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        int r, n, fd;

        log_setup();

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

        notify_stop = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);
        r = sd_event_loop(context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
