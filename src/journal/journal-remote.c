/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "journal-file.h"
#include "journald-native.h"
#include "socket-util.h"
#include "mkdir.h"
#include "build.h"
#include "macro.h"
#include "strv.h"
#include "fileio.h"
#include "microhttpd-util.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

#include "journal-remote-parse.h"
#include "journal-remote-write.h"

#define REMOTE_JOURNAL_PATH "/var/log/journal/" SD_ID128_FORMAT_STR "/remote-%s.journal"

static char* arg_output = NULL;
static char* arg_url = NULL;
static char* arg_getter = NULL;
static char* arg_listen_raw = NULL;
static char* arg_listen_http = NULL;
static char* arg_listen_https = NULL;
static char** arg_files = NULL;
static int arg_compress = true;
static int arg_seal = false;
static int http_socket = -1, https_socket = -1;

static char *key_pem = NULL;
static char *cert_pem = NULL;
static char *trust_pem = NULL;

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int spawn_child(const char* child, char** argv) {
        int fd[2];
        pid_t parent_pid, child_pid;
        int r;

        if (pipe(fd) < 0) {
                log_error("Failed to create pager pipe: %m");
                return -errno;
        }

        parent_pid = getpid();

        child_pid = fork();
        if (child_pid < 0) {
                r = -errno;
                log_error("Failed to fork: %m");
                safe_close_pair(fd);
                return r;
        }

        /* In the child */
        if (child_pid == 0) {
                r = dup2(fd[1], STDOUT_FILENO);
                if (r < 0) {
                        log_error("Failed to dup pipe to stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                safe_close_pair(fd);

                /* Make sure the child goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                execvp(child, argv);
                log_error("Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        r = close(fd[1]);
        if (r < 0)
                log_warning("Failed to close write end of pipe: %m");

        return fd[0];
}

static int spawn_curl(char* url) {
        char **argv = STRV_MAKE("curl",
                                "-HAccept: application/vnd.fdo.journal",
                                "--silent",
                                "--show-error",
                                url);
        int r;

        r = spawn_child("curl", argv);
        if (r < 0)
                log_error("Failed to spawn curl: %m");
        return r;
}

static int spawn_getter(char *getter, char *url) {
        int r;
        _cleanup_strv_free_ char **words = NULL;

        assert(getter);
        words = strv_split_quoted(getter);
        if (!words)
                return log_oom();

        r = spawn_child(words[0], words);
        if (r < 0)
                log_error("Failed to spawn getter %s: %m", getter);

        return r;
}

static int open_output(Writer *s, const char* url) {
        _cleanup_free_ char *name, *output = NULL;
        char *c;
        int r;

        assert(url);
        name = strdup(url);
        if (!name)
                return log_oom();

        for(c = name; *c; c++) {
                if (*c == '/' || *c == ':' || *c == ' ')
                        *c = '~';
                else if (*c == '?') {
                        *c = '\0';
                        break;
                }
        }

        if (!arg_output) {
                sd_id128_t machine;
                r = sd_id128_get_machine(&machine);
                if (r < 0) {
                        log_error("failed to determine machine ID128: %s", strerror(-r));
                        return r;
                }

                r = asprintf(&output, REMOTE_JOURNAL_PATH,
                             SD_ID128_FORMAT_VAL(machine), name);
                if (r < 0)
                        return log_oom();
        } else {
                r = is_dir(arg_output, true);
                if (r > 0) {
                        r = asprintf(&output,
                                     "%s/remote-%s.journal", arg_output, name);
                        if (r < 0)
                                return log_oom();
                } else {
                        output = strdup(arg_output);
                        if (!output)
                                return log_oom();
                }
        }

        r = journal_file_open_reliably(output,
                                       O_RDWR|O_CREAT, 0640,
                                       arg_compress, arg_seal,
                                       &s->metrics,
                                       s->mmap,
                                       NULL, &s->journal);
        if (r < 0)
                log_error("Failed to open output journal %s: %s",
                          arg_output, strerror(-r));
        else
                log_info("Opened output file %s", s->journal->path);
        return r;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

typedef struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *event;
} MHDDaemonWrapper;

typedef struct RemoteServer {
        RemoteSource **sources;
        size_t sources_size;
        size_t active;

        sd_event *events;
        sd_event_source *sigterm_event, *sigint_event, *listen_event;

        Writer writer;

        Hashmap *daemons;
} RemoteServer;

/* This should go away as soon as µhttpd allows state to be passed around. */
static RemoteServer *server;

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata);
static int dispatch_raw_connection_event(sd_event_source *event,
                                         int fd,
                                         uint32_t revents,
                                         void *userdata);
static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata);

static int get_source_for_fd(RemoteServer *s, int fd, RemoteSource **source) {
        assert(fd >= 0);
        assert(source);

        if (!GREEDY_REALLOC0(s->sources, s->sources_size, fd + 1))
                return log_oom();

        if (s->sources[fd] == NULL) {
                s->sources[fd] = new0(RemoteSource, 1);
                if (!s->sources[fd])
                        return log_oom();
                s->sources[fd]->fd = -1;
                s->active++;
        }

        *source = s->sources[fd];
        return 0;
}

static int remove_source(RemoteServer *s, int fd) {
        RemoteSource *source;

        assert(s);
        assert(fd >= 0 && fd < (ssize_t) s->sources_size);

        source = s->sources[fd];
        if (source) {
                source_free(source);
                s->sources[fd] = NULL;
                s->active--;
        }

        close(fd);

        return 0;
}

static int add_source(RemoteServer *s, int fd, const char* name) {
        RemoteSource *source = NULL;
        _cleanup_free_ char *realname = NULL;
        int r;

        assert(s);
        assert(fd >= 0);

        if (name) {
                realname = strdup(name);
                if (!realname)
                        return log_oom();
        } else {
                r = asprintf(&realname, "fd:%d", fd);
                if (r < 0)
                        return log_oom();
        }

        log_debug("Creating source for fd:%d (%s)", fd, realname);

        r = get_source_for_fd(s, fd, &source);
        if (r < 0) {
                log_error("Failed to create source for fd:%d (%s)", fd, realname);
                return r;
        }
        assert(source);
        assert(source->fd < 0);
        source->fd = fd;

        r = sd_event_add_io(s->events, &source->event,
                            fd, EPOLLIN, dispatch_raw_source_event, s);
        if (r < 0) {
                log_error("Failed to register event source for fd:%d: %s",
                          fd, strerror(-r));
                goto error;
        }

        return 1; /* work to do */

 error:
        remove_source(s, fd);
        return r;
}

static int add_raw_socket(RemoteServer *s, int fd) {
        int r;

        r = sd_event_add_io(s->events, &s->listen_event, fd, EPOLLIN,
                            dispatch_raw_connection_event, s);
        if (r < 0) {
                close(fd);
                return r;
        }

        s->active ++;
        return 0;
}

static int setup_raw_socket(RemoteServer *s, const char *address) {
        int fd;

        fd = make_socket_fd(LOG_INFO, address, SOCK_STREAM | SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        return add_raw_socket(s, fd);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static RemoteSource *request_meta(void **connection_cls) {
        RemoteSource *source;

        assert(connection_cls);
        if (*connection_cls)
                return *connection_cls;

        source = new0(RemoteSource, 1);
        if (!source)
                return NULL;
        source->fd = -1;

        log_debug("Added RemoteSource as connection metadata %p", source);

        *connection_cls = source;
        return source;
}

static void request_meta_free(void *cls,
                              struct MHD_Connection *connection,
                              void **connection_cls,
                              enum MHD_RequestTerminationCode toe) {
        RemoteSource *s;

        assert(connection_cls);
        s = *connection_cls;

        log_debug("Cleaning up connection metadata %p", s);
        source_free(s);
        *connection_cls = NULL;
}

static int process_http_upload(
                struct MHD_Connection *connection,
                const char *upload_data,
                size_t *upload_data_size,
                RemoteSource *source) {

        bool finished = false;
        int r;

        assert(source);

        log_debug("request_handler_upload: connection %p, %zu bytes",
                  connection, *upload_data_size);

        if (*upload_data_size) {
                log_info("Received %zu bytes", *upload_data_size);

                r = push_data(source, upload_data, *upload_data_size);
                if (r < 0) {
                        log_error("Failed to store received data of size %zu: %s",
                                  *upload_data_size, strerror(-r));
                        return mhd_respond_oom(connection);
                }
                *upload_data_size = 0;
        } else
                finished = true;

        while (true) {
                r = process_source(source, &server->writer, arg_compress, arg_seal);
                if (r == -E2BIG)
                        log_warning("Entry too big, skipped");
                else if (r == -EAGAIN || r == -EWOULDBLOCK)
                        break;
                else if (r < 0) {
                        log_warning("Failed to process data for connection %p", connection);
                        return mhd_respondf(connection, MHD_HTTP_UNPROCESSABLE_ENTITY,
                                            "Processing failed: %s", strerror(-r));
                }
        }

        if (!finished)
                return MHD_YES;

        /* The upload is finished */

        if (source_non_empty(source)) {
                log_warning("EOF reached with incomplete data");
                return mhd_respond(connection, MHD_HTTP_EXPECTATION_FAILED,
                                   "Trailing data not processed.");
        }

        return mhd_respond(connection, MHD_HTTP_ACCEPTED, "OK.\n");
};

static int request_handler(
                void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **connection_cls) {

        const char *header;
        int r ,code;

        assert(connection);
        assert(connection_cls);
        assert(url);
        assert(method);

        log_debug("Handling a connection %s %s %s", method, url, version);

        if (*connection_cls)
                return process_http_upload(connection,
                                           upload_data, upload_data_size,
                                           *connection_cls);

        if (!streq(method, "POST"))
                return mhd_respond(connection, MHD_HTTP_METHOD_NOT_ACCEPTABLE,
                                   "Unsupported method.\n");

        if (!streq(url, "/upload"))
                return mhd_respond(connection, MHD_HTTP_NOT_FOUND,
                                   "Not found.\n");

        header = MHD_lookup_connection_value(connection,
                                             MHD_HEADER_KIND, "Content-Type");
        if (!header || !streq(header, "application/vnd.fdo.journal"))
                return mhd_respond(connection, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE,
                                   "Content-Type: application/vnd.fdo.journal"
                                   " is required.\n");

        if (trust_pem) {
                r = check_permissions(connection, &code);
                if (r < 0)
                        return code;
        }

        if (!request_meta(connection_cls))
                return respond_oom(connection);
        return MHD_YES;
}

static int setup_microhttpd_server(RemoteServer *s, int fd, bool https) {
        struct MHD_OptionItem opts[] = {
                { MHD_OPTION_NOTIFY_COMPLETED, (intptr_t) request_meta_free},
                { MHD_OPTION_EXTERNAL_LOGGER, (intptr_t) microhttpd_logger},
                { MHD_OPTION_LISTEN_SOCKET, fd},
                { MHD_OPTION_END},
                { MHD_OPTION_END},
                { MHD_OPTION_END},
                { MHD_OPTION_END}};
        int opts_pos = 3;
        int flags =
                MHD_USE_DEBUG |
                MHD_USE_PEDANTIC_CHECKS |
                MHD_USE_EPOLL_LINUX_ONLY |
                MHD_USE_DUAL_STACK;

        const union MHD_DaemonInfo *info;
        int r, epoll_fd;
        MHDDaemonWrapper *d;

        assert(fd >= 0);

        r = fd_nonblock(fd, true);
        if (r < 0) {
                log_error("Failed to make fd:%d nonblocking: %s", fd, strerror(-r));
                return r;
        }

        if (https) {
                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_KEY, 0, key_pem};
                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_CERT, 0, cert_pem};

                flags |= MHD_USE_SSL;

                if (trust_pem)
                        opts[opts_pos++] = (struct MHD_OptionItem)
                                {MHD_OPTION_HTTPS_MEM_TRUST, 0, trust_pem};
        }

        d = new(MHDDaemonWrapper, 1);
        if (!d)
                return log_oom();

        d->fd = (uint64_t) fd;

        d->daemon = MHD_start_daemon(flags, 0,
                                     NULL, NULL,
                                     request_handler, NULL,
                                     MHD_OPTION_ARRAY, opts,
                                     MHD_OPTION_END);
        if (!d->daemon) {
                log_error("Failed to start µhttp daemon");
                r = -EINVAL;
                goto error;
        }

        log_debug("Started MHD %s daemon on fd:%d (wrapper @ %p)",
                  https ? "HTTPS" : "HTTP", fd, d);


        info = MHD_get_daemon_info(d->daemon, MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY);
        if (!info) {
                log_error("µhttp returned NULL daemon info");
                r = -ENOTSUP;
                goto error;
        }

        epoll_fd = info->listen_fd;
        if (epoll_fd < 0) {
                log_error("µhttp epoll fd is invalid");
                r = -EUCLEAN;
                goto error;
        }

        r = sd_event_add_io(s->events, &d->event,
                            epoll_fd, EPOLLIN, dispatch_http_event, d);
        if (r < 0) {
                log_error("Failed to add event callback: %s", strerror(-r));
                goto error;
        }

        r = hashmap_ensure_allocated(&s->daemons, uint64_hash_func, uint64_compare_func);
        if (r < 0) {
                log_oom();
                goto error;
        }

        r = hashmap_put(s->daemons, &d->fd, d);
        if (r < 0) {
                log_error("Failed to add daemon to hashmap: %s", strerror(-r));
                goto error;
        }

        s->active ++;
        return 0;

error:
        MHD_stop_daemon(d->daemon);
        free(d->daemon);
        free(d);
        return r;
}

static int setup_microhttpd_socket(RemoteServer *s,
                                   const char *address,
                                   bool https) {
        int fd;

        fd = make_socket_fd(LOG_INFO, address, SOCK_STREAM | SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        return setup_microhttpd_server(s, fd, https);
}

static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata) {
        MHDDaemonWrapper *d = userdata;
        int r;

        assert(d);

        log_info("%s", __func__);

        r = MHD_run(d->daemon);
        if (r == MHD_NO) {
                log_error("MHD_run failed!");
                // XXX: unregister daemon
                return -EINVAL;
        }

        return 1; /* work to do */
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int dispatch_sigterm(sd_event_source *event,
                            const struct signalfd_siginfo *si,
                            void *userdata) {
        RemoteServer *s = userdata;

        assert(s);

        log_received_signal(LOG_INFO, si);

        sd_event_exit(s->events, 0);
        return 0;
}

static int setup_signals(RemoteServer *s) {
        sigset_t mask;
        int r;

        assert(s);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        r = sd_event_add_signal(s->events, &s->sigterm_event, SIGTERM, dispatch_sigterm, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->events, &s->sigint_event, SIGINT, dispatch_sigterm, s);
        if (r < 0)
                return r;

        return 0;
}

static int fd_fd(const char *spec) {
        int fd, r;

        r = safe_atoi(spec, &fd);
        if (r < 0)
                return r;

        if (fd >= 0)
                return -ENOENT;

        return -fd;
}


static int remoteserver_init(RemoteServer *s) {
        int r, n, fd;
        const char *output_name = NULL;
        char **file;

        assert(s);

        sd_event_default(&s->events);

        setup_signals(s);

        assert(server == NULL);
        server = s;

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s",
                          strerror(-n));
                return n;
        } else
                log_info("Received %d descriptors", n);

        if (MAX(http_socket, https_socket) >= SD_LISTEN_FDS_START + n) {
                log_error("Received fewer sockets than expected");
                return -EBADFD;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                if (sd_is_socket(fd, AF_UNSPEC, 0, false)) {
                        log_info("Received a listening socket (fd:%d)", fd);

                        if (fd == http_socket)
                                r = setup_microhttpd_server(s, fd, false);
                        else if (fd == https_socket)
                                r = setup_microhttpd_server(s, fd, true);
                        else
                                r = add_raw_socket(s, fd);
                } else if (sd_is_socket(fd, AF_UNSPEC, 0, true)) {
                        log_info("Received a connection socket (fd:%d)", fd);

                        r = add_source(s, fd, NULL);
                } else {
                        log_error("Unknown socket passed on fd:%d", fd);

                        return -EINVAL;
                }

                if(r < 0) {
                        log_error("Failed to register socket (fd:%d): %s",
                                  fd, strerror(-r));
                        return r;
                }

                output_name = "socket";
        }

        if (arg_url) {
                _cleanup_free_ char *url = NULL;
                _cleanup_strv_free_ char **urlv = strv_new(arg_url, "/entries", NULL);
                if (!urlv)
                        return log_oom();
                url = strv_join(urlv, "");
                if (!url)
                        return log_oom();

                if (arg_getter) {
                        log_info("Spawning getter %s...", url);
                        fd = spawn_getter(arg_getter, url);
                } else {
                        log_info("Spawning curl %s...", url);
                        fd = spawn_curl(url);
                }
                if (fd < 0)
                        return fd;

                r = add_source(s, fd, arg_url);
                if (r < 0)
                        return r;

                output_name = arg_url;
        }

        if (arg_listen_raw) {
                log_info("Listening on a socket...");
                r = setup_raw_socket(s, arg_listen_raw);
                if (r < 0)
                        return r;

                output_name = arg_listen_raw;
        }

        if (arg_listen_http) {
                r = setup_microhttpd_socket(s, arg_listen_http, false);
                if (r < 0)
                        return r;

                output_name = arg_listen_http;
        }

        if (arg_listen_https) {
                r = setup_microhttpd_socket(s, arg_listen_https, true);
                if (r < 0)
                        return r;

                output_name = arg_listen_https;
        }

        STRV_FOREACH(file, arg_files) {
                if (streq(*file, "-")) {
                        log_info("Reading standard input...");

                        fd = STDIN_FILENO;
                        output_name = "stdin";
                } else {
                        log_info("Reading file %s...", *file);

                        fd = open(*file, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                        if (fd < 0) {
                                log_error("Failed to open %s: %m", *file);
                                return -errno;
                        }
                        output_name = *file;
                }

                r = add_source(s, fd, output_name);
                if (r < 0)
                        return r;
        }

        if (s->active == 0) {
                log_error("Zarro sources specified");
                return -EINVAL;
        }

        if (!!n + !!arg_url + !!arg_listen_raw + !!arg_files)
                output_name = "multiple";

        r = writer_init(&s->writer);
        if (r < 0)
                return r;

        r = open_output(&s->writer, output_name);
        return r;
}

static int server_destroy(RemoteServer *s) {
        int r;
        size_t i;
        MHDDaemonWrapper *d;

        r = writer_close(&s->writer);

        while ((d = hashmap_steal_first(s->daemons))) {
                MHD_stop_daemon(d->daemon);
                sd_event_source_unref(d->event);
                free(d);
        }

        hashmap_free(s->daemons);

        assert(s->sources_size == 0 || s->sources);
        for (i = 0; i < s->sources_size; i++)
                remove_source(s, i);

        free(s->sources);

        sd_event_source_unref(s->sigterm_event);
        sd_event_source_unref(s->sigint_event);
        sd_event_source_unref(s->listen_event);
        sd_event_unref(s->events);

        /* fds that we're listening on remain open... */

        return r;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata) {

        RemoteServer *s = userdata;
        RemoteSource *source;
        int r;

        assert(fd >= 0 && fd < (ssize_t) s->sources_size);
        source = s->sources[fd];
        assert(source->fd == fd);

        r = process_source(source, &s->writer, arg_compress, arg_seal);
        if (source->state == STATE_EOF) {
                log_info("EOF reached with source fd:%d (%s)",
                         source->fd, source->name);
                if (source_non_empty(source))
                        log_warning("EOF reached with incomplete data");
                remove_source(s, source->fd);
                log_info("%zd active source remaining", s->active);
        } else if (r == -E2BIG) {
                log_error("Entry too big, skipped");
                r = 1;
        }

        return r;
}

static int accept_connection(const char* type, int fd, SocketAddress *addr) {
        int fd2, r;

        log_debug("Accepting new %s connection on fd:%d", type, fd);
        fd2 = accept4(fd, &addr->sockaddr.sa, &addr->size, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd2 < 0) {
                log_error("accept() on fd:%d failed: %m", fd);
                return -errno;
        }

        switch(socket_address_family(addr)) {
        case AF_INET:
        case AF_INET6: {
                char* _cleanup_free_ a = NULL;

                r = socket_address_print(addr, &a);
                if (r < 0) {
                        log_error("socket_address_print(): %s", strerror(-r));
                        close(fd2);
                        return r;
                }

                log_info("Accepted %s %s connection from %s",
                         type,
                         socket_address_family(addr) == AF_INET ? "IP" : "IPv6",
                         a);

                return fd2;
        };
        default:
                log_error("Rejected %s connection with unsupported family %d",
                          type, socket_address_family(addr));
                close(fd2);

                return -EINVAL;
        }
}

static int dispatch_raw_connection_event(sd_event_source *event,
                                         int fd,
                                         uint32_t revents,
                                         void *userdata) {
        RemoteServer *s = userdata;
        int fd2;
        SocketAddress addr = {
                .size = sizeof(union sockaddr_union),
                .type = SOCK_STREAM,
        };

        fd2 = accept_connection("raw", fd, &addr);
        if (fd2 < 0)
                return fd2;

        return add_source(s, fd2, NULL);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int help(void) {
        printf("%s [OPTIONS...] {FILE|-}...\n\n"
               "Write external journal events to a journal file.\n\n"
               "Options:\n"
               "  --url=URL            Read events from systemd-journal-gatewayd at URL\n"
               "  --getter=COMMAND     Read events from the output of COMMAND\n"
               "  --listen-raw=ADDR    Listen for connections at ADDR\n"
               "  --listen-http=ADDR   Listen for HTTP connections at ADDR\n"
               "  --listen-https=ADDR  Listen for HTTPS connections at ADDR\n"
               "  -o --output=FILE|DIR Write output to FILE or DIR/external-*.journal\n"
               "  --[no-]compress      Use XZ-compression in the output journal (default: yes)\n"
               "  --[no-]seal          Use Event sealing in the output journal (default: no)\n"
               "  -h --help            Show this help and exit\n"
               "  --version            Print version string and exit\n"
               "\n"
               "Note: file descriptors from sd_listen_fds() will be consumed, too.\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_URL,
                ARG_LISTEN_RAW,
                ARG_LISTEN_HTTP,
                ARG_LISTEN_HTTPS,
                ARG_GETTER,
                ARG_COMPRESS,
                ARG_NO_COMPRESS,
                ARG_SEAL,
                ARG_NO_SEAL,
                ARG_KEY,
                ARG_CERT,
                ARG_TRUST,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "url",          required_argument, NULL, ARG_URL          },
                { "getter",       required_argument, NULL, ARG_GETTER       },
                { "listen-raw",   required_argument, NULL, ARG_LISTEN_RAW   },
                { "listen-http",  required_argument, NULL, ARG_LISTEN_HTTP  },
                { "listen-https", required_argument, NULL, ARG_LISTEN_HTTPS },
                { "output",       required_argument, NULL, 'o'              },
                { "compress",     no_argument,       NULL, ARG_COMPRESS     },
                { "no-compress",  no_argument,       NULL, ARG_NO_COMPRESS  },
                { "seal",         no_argument,       NULL, ARG_SEAL         },
                { "no-seal",      no_argument,       NULL, ARG_NO_SEAL      },
                { "key",          required_argument, NULL, ARG_KEY          },
                { "cert",         required_argument, NULL, ARG_CERT         },
                { "trust",        required_argument, NULL, ARG_TRUST        },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0 /* done */;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case ARG_URL:
                        if (arg_url) {
                                log_error("cannot currently set more than one --url");
                                return -EINVAL;
                        }

                        arg_url = optarg;
                        break;

                case ARG_GETTER:
                        if (arg_getter) {
                                log_error("cannot currently use --getter more than once");
                                return -EINVAL;
                        }

                        arg_getter = optarg;
                        break;

                case ARG_LISTEN_RAW:
                        if (arg_listen_raw) {
                                log_error("cannot currently use --listen-raw more than once");
                                return -EINVAL;
                        }

                        arg_listen_raw = optarg;
                        break;

                case ARG_LISTEN_HTTP:
                        if (arg_listen_http || http_socket >= 0) {
                                log_error("cannot currently use --listen-http more than once");
                                return -EINVAL;
                        }

                        r = fd_fd(optarg);
                        if (r >= 0)
                                http_socket = r;
                        else if (r == -ENOENT)
                                arg_listen_http = optarg;
                        else {
                                log_error("Invalid port/fd specification %s: %s",
                                          optarg, strerror(-r));
                                return -EINVAL;
                        }

                        break;

                case ARG_LISTEN_HTTPS:
                        if (arg_listen_https || https_socket >= 0) {
                                log_error("cannot currently use --listen-https more than once");
                                return -EINVAL;
                        }

                        r = fd_fd(optarg);
                        if (r >= 0)
                                https_socket = r;
                        else if (r == -ENOENT)
                                arg_listen_https = optarg;
                        else {
                                log_error("Invalid port/fd specification %s: %s",
                                          optarg, strerror(-r));
                                return -EINVAL;
                        }

                        break;

                case ARG_KEY:
                        if (key_pem) {
                                log_error("Key file specified twice");
                                return -EINVAL;
                        }
                        r = read_full_file(optarg, &key_pem, NULL);
                        if (r < 0) {
                                log_error("Failed to read key file: %s", strerror(-r));
                                return r;
                        }
                        assert(key_pem);
                        break;

                case ARG_CERT:
                        if (cert_pem) {
                                log_error("Certificate file specified twice");
                                return -EINVAL;
                        }
                        r = read_full_file(optarg, &cert_pem, NULL);
                        if (r < 0) {
                                log_error("Failed to read certificate file: %s", strerror(-r));
                                return r;
                        }
                        assert(cert_pem);
                        break;

                case ARG_TRUST:
#ifdef HAVE_GNUTLS
                        if (trust_pem) {
                                log_error("CA certificate file specified twice");
                                return -EINVAL;
                        }
                        r = read_full_file(optarg, &trust_pem, NULL);
                        if (r < 0) {
                                log_error("Failed to read CA certificate file: %s", strerror(-r));
                                return r;
                        }
                        assert(trust_pem);
                        break;
#else
                        log_error("Option --trust is not available.");
#endif

                case 'o':
                        if (arg_output) {
                                log_error("cannot use --output/-o more than once");
                                return -EINVAL;
                        }

                        arg_output = optarg;
                        break;

                case ARG_COMPRESS:
                        arg_compress = true;
                        break;
                case ARG_NO_COMPRESS:
                        arg_compress = false;
                        break;
                case ARG_SEAL:
                        arg_seal = true;
                        break;
                case ARG_NO_SEAL:
                        arg_seal = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }

        if (arg_listen_https && !(key_pem && cert_pem)) {
                log_error("Options --key and --cert must be used when https sources are specified");
                return -EINVAL;
        }

        if (optind < argc)
                arg_files = argv + optind;

        return 1 /* work to do */;
}

static int setup_gnutls_logger(void) {
        if (!arg_listen_http && !arg_listen_https)
                return 0;

#ifdef HAVE_GNUTLS
        gnutls_global_set_log_function(log_func_gnutls);
        gnutls_global_set_log_level(GNUTLS_LOG_LEVEL);
#endif

        return 0;
}

int main(int argc, char **argv) {
        RemoteServer s = {};
        int r, r2;

        log_set_max_level(LOG_DEBUG);
        log_show_color(true);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

        r = setup_gnutls_logger();
        if (r < 0)
                return EXIT_FAILURE;

        if (remoteserver_init(&s) < 0)
                return EXIT_FAILURE;

        log_debug("%s running as pid "PID_FMT,
                  program_invocation_short_name, getpid());
        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        while (s.active) {
                r = sd_event_get_state(s.events);
                if (r < 0)
                        break;
                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_run(s.events, -1);
                if (r < 0) {
                        log_error("Failed to run event loop: %s", strerror(-r));
                        break;
                }
        }

        log_info("Finishing after writing %" PRIu64 " entries", s.writer.seqnum);
        r2 = server_destroy(&s);

        sd_notify(false, "STATUS=Shutting down...");

        return r >= 0 && r2 >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
