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

#define BUFFER_SIZE 16384
#define _cleanup_freeaddrinfo_ _cleanup_(freeaddrinfop)

unsigned int total_clients = 0;

DEFINE_TRIVIAL_CLEANUP_FUNC(struct addrinfo *, freeaddrinfo);

struct proxy {
        int listen_fd;
        bool ignore_env;
        bool remote_is_inet;
        const char *remote_host;
        const char *remote_service;
};

struct connection {
        int fd;
        uint32_t events;
        sd_event_source *w;
        struct connection *c_destination;
        size_t buffer_filled_len;
        size_t buffer_sent_len;
        char buffer[BUFFER_SIZE];
};

static void free_connection(struct connection *c) {
        if (c != NULL) {
                log_debug("Freeing fd=%d (conn %p).", c->fd, c);
                sd_event_source_unref(c->w);
                if (c->fd > 0)
                        close_nointr_nofail(c->fd);
                free(c);
        }
}

static int add_event_to_connection(struct connection *c, uint32_t events) {
        int r;

        log_debug("Have revents=%d. Adding revents=%d.", c->events, events);

        c->events |= events;

        r = sd_event_source_set_io_events(c->w, c->events);
        if (r < 0) {
                log_error("Error %d setting revents: %s", r, strerror(-r));
                return r;
        }

        r = sd_event_source_set_enabled(c->w, SD_EVENT_ON);
        if (r < 0) {
                log_error("Error %d enabling source: %s", r, strerror(-r));
                return r;
        }

        return 0;
}

static int remove_event_from_connection(struct connection *c, uint32_t events) {
        int r;

        log_debug("Have revents=%d. Removing revents=%d.", c->events, events);

        c->events &= ~events;

        r = sd_event_source_set_io_events(c->w, c->events);
        if (r < 0) {
                log_error("Error %d setting revents: %s", r, strerror(-r));
                return r;
        }

        if (c->events == 0) {
            r = sd_event_source_set_enabled(c->w, SD_EVENT_OFF);
            if (r < 0) {
                    log_error("Error %d disabling source: %s", r, strerror(-r));
                    return r;
            }
        }

        return 0;
}

static int send_buffer(struct connection *sender) {
        struct connection *receiver = sender->c_destination;
        ssize_t len;
        int r = 0;

        /* We cannot assume that even a partial send() indicates that
         * the next send() will return EAGAIN or EWOULDBLOCK. Loop until
         * it does. */
        while (sender->buffer_filled_len > sender->buffer_sent_len) {
                len = send(receiver->fd, sender->buffer + sender->buffer_sent_len, sender->buffer_filled_len - sender->buffer_sent_len, 0);
                log_debug("send(%d, ...)=%zd", receiver->fd, len);
                if (len < 0) {
                        if (errno != EWOULDBLOCK && errno != EAGAIN) {
                                log_error("Error %d in send to fd=%d: %m", errno, receiver->fd);
                                return -errno;
                        }
                        else {
                                /* send() is in a would-block state. */
                                break;
                        }
                }

                /* len < 0 can't occur here. len == 0 is possible but
                 * undefined behavior for nonblocking send(). */
                assert(len > 0);
                sender->buffer_sent_len += len;
        }

        log_debug("send(%d, ...) completed with %zu bytes still buffered.", receiver->fd, sender->buffer_filled_len - sender->buffer_sent_len);

        /* Detect a would-block state or partial send. */
        if (sender->buffer_filled_len > sender->buffer_sent_len) {

                /* If the buffer is full, disable events coming for recv. */
                if (sender->buffer_filled_len == BUFFER_SIZE) {
                    r = remove_event_from_connection(sender, EPOLLIN);
                    if (r < 0) {
                            log_error("Error %d disabling EPOLLIN for fd=%d: %s", r, sender->fd, strerror(-r));
                            return r;
                    }
                }

                /* Watch for when the recipient can be sent data again. */
                r = add_event_to_connection(receiver, EPOLLOUT);
                if (r < 0) {
                        log_error("Error %d enabling EPOLLOUT for fd=%d: %s", r, receiver->fd, strerror(-r));
                        return r;
                }
                log_debug("Done with recv for fd=%d. Waiting on send for fd=%d.", sender->fd, receiver->fd);
                return r;
        }

        /* If we sent everything without any issues (would-block or
         * partial send), the buffer is now empty. */
        sender->buffer_filled_len = 0;
        sender->buffer_sent_len = 0;

        /* Enable the sender's receive watcher, in case the buffer was
         * full and we disabled it. */
        r = add_event_to_connection(sender, EPOLLIN);
        if (r < 0) {
                log_error("Error %d enabling EPOLLIN for fd=%d: %s", r, sender->fd, strerror(-r));
                return r;
        }

        /* Disable the other side's send watcher, as we have no data to send now. */
        r = remove_event_from_connection(receiver, EPOLLOUT);
        if (r < 0) {
                log_error("Error %d disabling EPOLLOUT for fd=%d: %s", r, receiver->fd, strerror(-r));
                return r;
        }

        return 0;
}

static int transfer_data_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct connection *c = (struct connection *) userdata;
        int r = 0;
        ssize_t len;

        assert(revents & (EPOLLIN | EPOLLOUT));
        assert(fd == c->fd);
        assert(s == c->w);

        log_debug("Got event revents=%d from fd=%d (conn %p).", revents, fd, c);

        if (revents & EPOLLIN) {
                log_debug("About to recv up to %zu bytes from fd=%d (%zu/BUFFER_SIZE).", BUFFER_SIZE - c->buffer_filled_len, fd, c->buffer_filled_len);

                /* Receive until the buffer's full, there's no more data,
                 * or the client/server disconnects. */
                while (c->buffer_filled_len < BUFFER_SIZE) {
                        len = recv(fd, c->buffer + c->buffer_filled_len, BUFFER_SIZE - c->buffer_filled_len, 0);
                        log_debug("recv(%d, ...)=%zd", fd, len);
                        if (len < 0) {
                                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                                        log_error("Error %d in recv from fd=%d: %m", errno, fd);
                                        return -errno;
                                }
                                else {
                                        /* recv() is in a blocking state. */
                                        break;
                                }
                        }
                        else if (len == 0) {
                                log_debug("Clean disconnection from fd=%d", fd);
                                total_clients--;
                                free_connection(c->c_destination);
                                free_connection(c);
                                return 0;
                        }

                        assert(len > 0);
                        log_debug("Recording that the buffer got %zd more bytes full.", len);
                        c->buffer_filled_len += len;
                        log_debug("Buffer now has %zu bytes full.", c->buffer_filled_len);
                }

                /* Try sending the data immediately. */
                return send_buffer(c);
        }
        else {
                return send_buffer(c->c_destination);
        }

        return r;
}

/* Once sending to the server is ready, set up the real watchers. */
static int connected_to_server_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct sd_event *e = NULL;
        struct connection *c_server_to_client = (struct connection *) userdata;
        struct connection *c_client_to_server = c_server_to_client->c_destination;
        int r;

        assert(revents & EPOLLOUT);

        e = sd_event_get(s);

        /* Cancel the initial write watcher for the server. */
        sd_event_source_unref(s);

        log_debug("Connected to server. Initializing watchers for receiving data.");

        /* A recv watcher for the server. */
        r = sd_event_add_io(e, c_server_to_client->fd, EPOLLIN, transfer_data_cb, c_server_to_client, &c_server_to_client->w);
        if (r < 0) {
                log_error("Error %d creating recv watcher for fd=%d: %s", r, c_server_to_client->fd, strerror(-r));
                goto fail;
        }
        c_server_to_client->events = EPOLLIN;

        /* A recv watcher for the client. */
        r = sd_event_add_io(e, c_client_to_server->fd, EPOLLIN, transfer_data_cb, c_client_to_server, &c_client_to_server->w);
        if (r < 0) {
                log_error("Error %d creating recv watcher for fd=%d: %s", r, c_client_to_server->fd, strerror(-r));
                goto fail;
        }
        c_client_to_server->events = EPOLLIN;

goto finish;

fail:
        free_connection(c_client_to_server);
        free_connection(c_server_to_client);

finish:
        return r;
}

static int get_server_connection_fd(const struct proxy *proxy) {
        int server_fd;
        int r = -EBADF;
        int len;

        if (proxy->remote_is_inet) {
                int s;
                _cleanup_freeaddrinfo_ struct addrinfo *result = NULL;
                struct addrinfo hints = {.ai_family = AF_UNSPEC,
                                         .ai_socktype = SOCK_STREAM,
                                         .ai_flags = AI_PASSIVE};

                log_debug("Looking up address info for %s:%s", proxy->remote_host, proxy->remote_service);
                s = getaddrinfo(proxy->remote_host, proxy->remote_service, &hints, &result);
                if (s != 0) {
                        log_error("getaddrinfo error (%d): %s", s, gai_strerror(s));
                        return r;
                }

                if (result == NULL) {
                        log_error("getaddrinfo: no result");
                        return r;
                }

                /* @TODO: Try connecting to all results instead of just the first. */
                server_fd = socket(result->ai_family, result->ai_socktype | SOCK_NONBLOCK, result->ai_protocol);
                if (server_fd < 0) {
                        log_error("Error %d creating socket: %m", errno);
                        return r;
                }

                r = connect(server_fd, result->ai_addr, result->ai_addrlen);
                /* Ignore EINPROGRESS errors because they're expected for a nonblocking socket. */
                if (r < 0 && errno != EINPROGRESS) {
                        log_error("Error %d while connecting to socket %s:%s: %m", errno, proxy->remote_host, proxy->remote_service);
                        return r;
                }
        }
        else {
                struct sockaddr_un remote;

                server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
                if (server_fd < 0) {
                        log_error("Error %d creating socket: %m", errno);
                        return -EBADFD;
                }

                remote.sun_family = AF_UNIX;
                strncpy(remote.sun_path, proxy->remote_host, sizeof(remote.sun_path));
                len = strlen(remote.sun_path) + sizeof(remote.sun_family);
                r = connect(server_fd, (struct sockaddr *) &remote, len);
                if (r < 0 && errno != EINPROGRESS) {
                        log_error("Error %d while connecting to Unix domain socket %s: %m", errno, proxy->remote_host);
                        return -EBADFD;
                }
        }

        log_debug("Server connection is fd=%d", server_fd);
        return server_fd;
}

static int do_accept(sd_event *e, struct proxy *p, int fd) {
        struct connection *c_server_to_client = NULL;
        struct connection *c_client_to_server = NULL;
        int r = 0;
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);
        int client_fd, server_fd;

        client_fd = accept4(fd, (struct sockaddr *) &sa, &salen, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return -errno;
                log_error("Error %d accepting client connection: %m", errno);
                r = -errno;
                goto fail;
        }

        server_fd = get_server_connection_fd(p);
        if (server_fd < 0) {
                log_error("Error initiating server connection.");
                r = server_fd;
                goto fail;
        }

        c_client_to_server = new0(struct connection, 1);
        if (c_client_to_server == NULL) {
                log_oom();
                goto fail;
        }

        c_server_to_client = new0(struct connection, 1);
        if (c_server_to_client == NULL) {
                log_oom();
                goto fail;
        }

        c_client_to_server->fd = client_fd;
        c_server_to_client->fd = server_fd;

        if (sa.sa.sa_family == AF_INET || sa.sa.sa_family == AF_INET6) {
                char sa_str[INET6_ADDRSTRLEN];
                const char *success;

                success = inet_ntop(sa.sa.sa_family, &sa.in6.sin6_addr, sa_str, INET6_ADDRSTRLEN);
                if (success == NULL)
                        log_warning("Error %d calling inet_ntop: %m", errno);
                else
                        log_debug("Accepted client connection from %s as fd=%d", sa_str, c_client_to_server->fd);
        }
        else {
                log_debug("Accepted client connection (non-IP) as fd=%d", c_client_to_server->fd);
        }

        total_clients++;
        log_debug("Client fd=%d (conn %p) successfully connected. Total clients: %u", c_client_to_server->fd, c_client_to_server, total_clients);
        log_debug("Server fd=%d (conn %p) successfully initialized.", c_server_to_client->fd, c_server_to_client);

        /* Initialize watcher for send to server; this shows connectivity. */
        r = sd_event_add_io(e, c_server_to_client->fd, EPOLLOUT, connected_to_server_cb, c_server_to_client, &c_server_to_client->w);
        if (r < 0) {
                log_error("Error %d creating connectivity watcher for fd=%d: %s", r, c_server_to_client->fd, strerror(-r));
                goto fail;
        }

        /* Allow lookups of the opposite connection. */
        c_server_to_client->c_destination = c_client_to_server;
        c_client_to_server->c_destination = c_server_to_client;

        goto finish;

fail:
        log_warning("Accepting a client connection or connecting to the server failed.");
        free_connection(c_client_to_server);
        free_connection(c_server_to_client);

finish:
        return r;
}

static int accept_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct proxy *p = (struct proxy *) userdata;
        sd_event *e = NULL;
        int r = 0;

        assert(revents & EPOLLIN);

        e = sd_event_get(s);

        for (;;) {
                r = do_accept(e, p, fd);
                if (r == -EAGAIN || r == -EWOULDBLOCK)
                        break;
                if (r < 0) {
                        log_error("Error %d while trying to accept: %s", r, strerror(-r));
                        break;
                }
        }

        /* Re-enable the watcher. */
        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_error("Error %d while re-enabling listener with ONESHOT: %s", r, strerror(-r));
                return r;
        }

        /* Preserve the main loop even if a single accept() fails. */
        return 1;
}

static int run_main_loop(struct proxy *proxy) {
        _cleanup_event_source_unref_ sd_event_source *w_accept = NULL;
        _cleanup_event_unref_ sd_event *e = NULL;
        int r = EXIT_SUCCESS;

        r = sd_event_new(&e);
        if (r < 0) {
                log_error("Failed to allocate event loop: %s", strerror(-r));
                return r;
        }

        r = fd_nonblock(proxy->listen_fd, true);
        if (r < 0) {
                log_error("Failed to make listen file descriptor nonblocking: %s", strerror(-r));
                return r;
        }

        log_debug("Initializing main listener fd=%d", proxy->listen_fd);

        r = sd_event_add_io(e, proxy->listen_fd, EPOLLIN, accept_cb, proxy, &w_accept);
        if (r < 0) {
                log_error("Error %d while adding event IO source: %s", r, strerror(-r));
                return r;
        }

        /* Set the watcher to oneshot in case other processes are also
         * watching to accept(). */
        r = sd_event_source_set_enabled(w_accept, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_error("Error %d while setting event IO source to ONESHOT: %s", r, strerror(-r));
                return r;
        }

        log_debug("Initialized main listener. Entering loop.");

        return sd_event_loop(e);
}

static int help(void) {

        printf("%s hostname-or-ip port-or-service\n"
               "%s unix-domain-socket-path\n\n"
               "Inherit a socket. Bidirectionally proxy.\n\n"
               "  -h --help       Show this help\n"
               "  --version       Print version and exit\n"
               "  --ignore-env    Ignore expected systemd environment\n",
               program_invocation_short_name,
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[], struct proxy *p) {

        enum {
                ARG_VERSION = 0x100,
                ARG_IGNORE_ENV
        };

        static const struct option options[] = {
                { "help",       no_argument, NULL, 'h'           },
                { "version",    no_argument, NULL, ARG_VERSION   },
                { "ignore-env", no_argument, NULL, ARG_IGNORE_ENV},
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

                case ARG_IGNORE_ENV:
                        p->ignore_env = true;
                        continue;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind + 1 != argc && optind + 2 != argc) {
                log_error("Incorrect number of positional arguments.");
                help();
                return -EINVAL;
        }

        p->remote_host = argv[optind];
        assert(p->remote_host);

        p->remote_is_inet = p->remote_host[0] != '/';

        if (optind == argc - 2) {
                if (!p->remote_is_inet) {
                        log_error("A port or service is not allowed for Unix socket destinations.");
                        help();
                        return -EINVAL;
                }
                p->remote_service = argv[optind + 1];
                assert(p->remote_service);
        } else if (p->remote_is_inet) {
                log_error("A port or service is required for IP destinations.");
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        struct proxy p = {};
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv, &p);
        if (r <= 0)
                goto finish;

        p.listen_fd = SD_LISTEN_FDS_START;

        if (!p.ignore_env) {
                int n;
                n = sd_listen_fds(1);
                if (n == 0) {
                        log_error("Found zero inheritable sockets. Are you sure this is running as a socket-activated service?");
                        r = EXIT_FAILURE;
                        goto finish;
                } else if (n < 0) {
                        log_error("Error %d while finding inheritable sockets: %s", n, strerror(-n));
                        r = EXIT_FAILURE;
                        goto finish;
                } else if (n > 1) {
                        log_error("Can't listen on more than one socket.");
                        r = EXIT_FAILURE;
                        goto finish;
                }
        }

        r = sd_is_socket(p.listen_fd, 0, SOCK_STREAM, 1);
        if (r < 0) {
                log_error("Error %d while checking inherited socket: %s", r, strerror(-r));
                goto finish;
        }

        log_info("Starting the socket activation proxy with listener fd=%d.", p.listen_fd);

        r = run_main_loop(&p);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
