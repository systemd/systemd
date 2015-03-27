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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>

#include "sd-daemon.h"
#include "journal-file.h"
#include "journald-native.h"
#include "socket-util.h"
#include "build.h"
#include "macro.h"
#include "strv.h"
#include "fileio.h"
#include "conf-parser.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

#include "journal-remote.h"
#include "journal-remote-write.h"

#define REMOTE_JOURNAL_PATH "/var/log/journal/remote"

#define PRIV_KEY_FILE CERTIFICATE_ROOT "/private/journal-remote.pem"
#define CERT_FILE     CERTIFICATE_ROOT "/certs/journal-remote.pem"
#define TRUST_FILE    CERTIFICATE_ROOT "/ca/trusted.pem"

static char* arg_url = NULL;
static char* arg_getter = NULL;
static char* arg_listen_raw = NULL;
static char* arg_listen_http = NULL;
static char* arg_listen_https = NULL;
static char** arg_files = NULL;
static int arg_compress = true;
static int arg_seal = false;
static int http_socket = -1, https_socket = -1;
static char** arg_gnutls_log = NULL;

static JournalWriteSplitMode arg_split_mode = JOURNAL_WRITE_SPLIT_HOST;
static char* arg_output = NULL;

static char *arg_key = NULL;
static char *arg_cert = NULL;
static char *arg_trust = NULL;
static bool arg_trust_all = false;

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int spawn_child(const char* child, char** argv) {
        int fd[2];
        pid_t parent_pid, child_pid;
        int r;

        if (pipe(fd) < 0)
                return log_error_errno(errno, "Failed to create pager pipe: %m");

        parent_pid = getpid();

        child_pid = fork();
        if (child_pid < 0) {
                r = -errno;
                log_error_errno(errno, "Failed to fork: %m");
                safe_close_pair(fd);
                return r;
        }

        /* In the child */
        if (child_pid == 0) {
                r = dup2(fd[1], STDOUT_FILENO);
                if (r < 0) {
                        log_error_errno(errno, "Failed to dup pipe to stdout: %m");
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
                log_error_errno(errno, "Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        r = close(fd[1]);
        if (r < 0)
                log_warning_errno(errno, "Failed to close write end of pipe: %m");

        return fd[0];
}

static int spawn_curl(const char* url) {
        char **argv = STRV_MAKE("curl",
                                "-HAccept: application/vnd.fdo.journal",
                                "--silent",
                                "--show-error",
                                url);
        int r;

        r = spawn_child("curl", argv);
        if (r < 0)
                log_error_errno(errno, "Failed to spawn curl: %m");
        return r;
}

static int spawn_getter(const char *getter, const char *url) {
        int r;
        _cleanup_strv_free_ char **words = NULL;

        assert(getter);
        r = strv_split_quoted(&words, getter, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to split getter option: %m");

        r = strv_extend(&words, url);
        if (r < 0)
                return log_error_errno(r, "Failed to create command line: %m");

        r = spawn_child(words[0], words);
        if (r < 0)
                log_error_errno(errno, "Failed to spawn getter %s: %m", getter);

        return r;
}

#define filename_escape(s) xescape((s), "/ ")

static int open_output(Writer *w, const char* host) {
        _cleanup_free_ char *_output = NULL;
        const char *output;
        int r;

        switch (arg_split_mode) {
        case JOURNAL_WRITE_SPLIT_NONE:
                output = arg_output ?: REMOTE_JOURNAL_PATH "/remote.journal";
                break;

        case JOURNAL_WRITE_SPLIT_HOST: {
                _cleanup_free_ char *name;

                assert(host);

                name = filename_escape(host);
                if (!name)
                        return log_oom();

                r = asprintf(&_output, "%s/remote-%s.journal",
                             arg_output ?: REMOTE_JOURNAL_PATH,
                             name);
                if (r < 0)
                        return log_oom();

                output = _output;
                break;
        }

        default:
                assert_not_reached("what?");
        }

        r = journal_file_open_reliably(output,
                                       O_RDWR|O_CREAT, 0640,
                                       arg_compress, arg_seal,
                                       &w->metrics,
                                       w->mmap,
                                       NULL, &w->journal);
        if (r < 0)
                log_error_errno(r, "Failed to open output journal %s: %m",
                                output);
        else
                log_debug("Opened output file %s", w->journal->path);
        return r;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int init_writer_hashmap(RemoteServer *s) {
        static const struct hash_ops *hash_ops[] = {
                [JOURNAL_WRITE_SPLIT_NONE] = NULL,
                [JOURNAL_WRITE_SPLIT_HOST] = &string_hash_ops,
        };

        assert(arg_split_mode >= 0 && arg_split_mode < (int) ELEMENTSOF(hash_ops));

        s->writers = hashmap_new(hash_ops[arg_split_mode]);
        if (!s->writers)
                return log_oom();

        return 0;
}

static int get_writer(RemoteServer *s, const char *host,
                      Writer **writer) {
        const void *key;
        _cleanup_writer_unref_ Writer *w = NULL;
        int r;

        switch(arg_split_mode) {
        case JOURNAL_WRITE_SPLIT_NONE:
                key = "one and only";
                break;

        case JOURNAL_WRITE_SPLIT_HOST:
                assert(host);
                key = host;
                break;

        default:
                assert_not_reached("what split mode?");
        }

        w = hashmap_get(s->writers, key);
        if (w)
                writer_ref(w);
        else {
                w = writer_new(s);
                if (!w)
                        return log_oom();

                if (arg_split_mode == JOURNAL_WRITE_SPLIT_HOST) {
                        w->hashmap_key = strdup(key);
                        if (!w->hashmap_key)
                                return log_oom();
                }

                r = open_output(w, host);
                if (r < 0)
                        return r;

                r = hashmap_put(s->writers, w->hashmap_key ?: key, w);
                if (r < 0)
                        return r;
        }

        *writer = w;
        w = NULL;
        return 0;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

/* This should go away as soon as µhttpd allows state to be passed around. */
static RemoteServer *server;

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata);
static int dispatch_raw_source_until_block(sd_event_source *event,
                                           void *userdata);
static int dispatch_blocking_source_event(sd_event_source *event,
                                          void *userdata);
static int dispatch_raw_connection_event(sd_event_source *event,
                                         int fd,
                                         uint32_t revents,
                                         void *userdata);
static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata);

static int get_source_for_fd(RemoteServer *s,
                             int fd, char *name, RemoteSource **source) {
        Writer *writer;
        int r;

        /* This takes ownership of name, but only on success. */

        assert(fd >= 0);
        assert(source);

        if (!GREEDY_REALLOC0(s->sources, s->sources_size, fd + 1))
                return log_oom();

        r = get_writer(s, name, &writer);
        if (r < 0)
                return log_warning_errno(r, "Failed to get writer for source %s: %m",
                                         name);

        if (s->sources[fd] == NULL) {
                s->sources[fd] = source_new(fd, false, name, writer);
                if (!s->sources[fd]) {
                        writer_unref(writer);
                        return log_oom();
                }

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
                /* this closes fd too */
                source_free(source);
                s->sources[fd] = NULL;
                s->active--;
        }

        return 0;
}

static int add_source(RemoteServer *s, int fd, char* name, bool own_name) {

        RemoteSource *source = NULL;
        int r;

        /* This takes ownership of name, even on failure, if own_name is true. */

        assert(s);
        assert(fd >= 0);
        assert(name);

        if (!own_name) {
                name = strdup(name);
                if (!name)
                        return log_oom();
        }

        r = get_source_for_fd(s, fd, name, &source);
        if (r < 0) {
                log_error_errno(r, "Failed to create source for fd:%d (%s): %m",
                                fd, name);
                free(name);
                return r;
        }

        r = sd_event_add_io(s->events, &source->event,
                            fd, EPOLLIN|EPOLLRDHUP|EPOLLPRI,
                            dispatch_raw_source_event, source);
        if (r == 0) {
                /* Add additional source for buffer processing. It will be
                 * enabled later. */
                r = sd_event_add_defer(s->events, &source->buffer_event,
                                       dispatch_raw_source_until_block, source);
                if (r == 0)
                        sd_event_source_set_enabled(source->buffer_event, SD_EVENT_OFF);
        } else if (r == -EPERM) {
                log_debug("Falling back to sd_event_add_defer for fd:%d (%s)", fd, name);
                r = sd_event_add_defer(s->events, &source->event,
                                       dispatch_blocking_source_event, source);
                if (r == 0)
                        sd_event_source_set_enabled(source->event, SD_EVENT_ON);
        }
        if (r < 0) {
                log_error_errno(r, "Failed to register event source for fd:%d: %m",
                                fd);
                goto error;
        }

        r = sd_event_source_set_description(source->event, name);
        if (r < 0) {
                log_error_errno(r, "Failed to set source name for fd:%d: %m", fd);
                goto error;
        }

        return 1; /* work to do */

 error:
        remove_source(s, fd);
        return r;
}

static int add_raw_socket(RemoteServer *s, int fd) {
        int r;
        _cleanup_close_ int fd_ = fd;
        char name[sizeof("raw-socket-")-1 + DECIMAL_STR_MAX(int) + 1];

        assert(fd >= 0);

        r = sd_event_add_io(s->events, &s->listen_event,
                            fd, EPOLLIN,
                            dispatch_raw_connection_event, s);
        if (r < 0)
                return r;

        xsprintf(name, "raw-socket-%d", fd);

        r = sd_event_source_set_description(s->listen_event, name);
        if (r < 0)
                return r;

        fd_ = -1;
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

static int request_meta(void **connection_cls, int fd, char *hostname) {
        RemoteSource *source;
        Writer *writer;
        int r;

        assert(connection_cls);
        if (*connection_cls)
                return 0;

        r = get_writer(server, hostname, &writer);
        if (r < 0)
                return log_warning_errno(r, "Failed to get writer for source %s: %m",
                                         hostname);

        source = source_new(fd, true, hostname, writer);
        if (!source) {
                writer_unref(writer);
                return log_oom();
        }

        log_debug("Added RemoteSource as connection metadata %p", source);

        *connection_cls = source;
        return 0;
}

static void request_meta_free(void *cls,
                              struct MHD_Connection *connection,
                              void **connection_cls,
                              enum MHD_RequestTerminationCode toe) {
        RemoteSource *s;

        assert(connection_cls);
        s = *connection_cls;

        if (s) {
                log_debug("Cleaning up connection metadata %p", s);
                source_free(s);
                *connection_cls = NULL;
        }
}

static int process_http_upload(
                struct MHD_Connection *connection,
                const char *upload_data,
                size_t *upload_data_size,
                RemoteSource *source) {

        bool finished = false;
        size_t remaining;
        int r;

        assert(source);

        log_trace("%s: connection %p, %zu bytes",
                  __func__, connection, *upload_data_size);

        if (*upload_data_size) {
                log_trace("Received %zu bytes", *upload_data_size);

                r = push_data(source, upload_data, *upload_data_size);
                if (r < 0)
                        return mhd_respond_oom(connection);

                *upload_data_size = 0;
        } else
                finished = true;

        while (true) {
                r = process_source(source, arg_compress, arg_seal);
                if (r == -EAGAIN)
                        break;
                else if (r < 0) {
                        log_warning("Failed to process data for connection %p", connection);
                        if (r == -E2BIG)
                                return mhd_respondf(connection,
                                                    MHD_HTTP_REQUEST_ENTITY_TOO_LARGE,
                                                    "Entry is too large, maximum is %u bytes.\n",
                                                    DATA_SIZE_MAX);
                        else
                                return mhd_respondf(connection,
                                                    MHD_HTTP_UNPROCESSABLE_ENTITY,
                                                    "Processing failed: %s.", strerror(-r));
                }
        }

        if (!finished)
                return MHD_YES;

        /* The upload is finished */

        remaining = source_non_empty(source);
        if (remaining > 0) {
                log_warning("Premature EOFbyte. %zu bytes lost.", remaining);
                return mhd_respondf(connection, MHD_HTTP_EXPECTATION_FAILED,
                                    "Premature EOF. %zu bytes of trailing data not processed.",
                                    remaining);
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
        int r, code, fd;
        _cleanup_free_ char *hostname = NULL;

        assert(connection);
        assert(connection_cls);
        assert(url);
        assert(method);

        log_trace("Handling a connection %s %s %s", method, url, version);

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

        {
                const union MHD_ConnectionInfo *ci;

                ci = MHD_get_connection_info(connection,
                                             MHD_CONNECTION_INFO_CONNECTION_FD);
                if (!ci) {
                        log_error("MHD_get_connection_info failed: cannot get remote fd");
                        return mhd_respond(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                           "Cannot check remote address");
                }

                fd = ci->connect_fd;
                assert(fd >= 0);
        }

        if (server->check_trust) {
                r = check_permissions(connection, &code, &hostname);
                if (r < 0)
                        return code;
        } else {
                r = getnameinfo_pretty(fd, &hostname);
                if (r < 0) {
                        return mhd_respond(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                           "Cannot check remote hostname");
                }
        }

        assert(hostname);

        r = request_meta(connection_cls, fd, hostname);
        if (r == -ENOMEM)
                return respond_oom(connection);
        else if (r < 0)
                return mhd_respond(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   strerror(-r));

        hostname = NULL;
        return MHD_YES;
}

static int setup_microhttpd_server(RemoteServer *s,
                                   int fd,
                                   const char *key,
                                   const char *cert,
                                   const char *trust) {
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
        if (r < 0)
                return log_error_errno(r, "Failed to make fd:%d nonblocking: %m", fd);

        if (key) {
                assert(cert);

                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_KEY, 0, (char*) key};
                opts[opts_pos++] = (struct MHD_OptionItem)
                        {MHD_OPTION_HTTPS_MEM_CERT, 0, (char*) cert};

                flags |= MHD_USE_SSL;

                if (trust)
                        opts[opts_pos++] = (struct MHD_OptionItem)
                                {MHD_OPTION_HTTPS_MEM_TRUST, 0, (char*) trust};
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
                  key ? "HTTPS" : "HTTP", fd, d);


        info = MHD_get_daemon_info(d->daemon, MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY);
        if (!info) {
                log_error("µhttp returned NULL daemon info");
                r = -EOPNOTSUPP;
                goto error;
        }

        epoll_fd = info->listen_fd;
        if (epoll_fd < 0) {
                log_error("µhttp epoll fd is invalid");
                r = -EUCLEAN;
                goto error;
        }

        r = sd_event_add_io(s->events, &d->event,
                            epoll_fd, EPOLLIN,
                            dispatch_http_event, d);
        if (r < 0) {
                log_error_errno(r, "Failed to add event callback: %m");
                goto error;
        }

        r = sd_event_source_set_description(d->event, "epoll-fd");
        if (r < 0) {
                log_error_errno(r, "Failed to set source name: %m");
                goto error;
        }

        r = hashmap_ensure_allocated(&s->daemons, &uint64_hash_ops);
        if (r < 0) {
                log_oom();
                goto error;
        }

        r = hashmap_put(s->daemons, &d->fd, d);
        if (r < 0) {
                log_error_errno(r, "Failed to add daemon to hashmap: %m");
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
                                   const char *key,
                                   const char *cert,
                                   const char *trust) {
        int fd;

        fd = make_socket_fd(LOG_DEBUG, address, SOCK_STREAM | SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        return setup_microhttpd_server(s, fd, key, cert, trust);
}

static int dispatch_http_event(sd_event_source *event,
                               int fd,
                               uint32_t revents,
                               void *userdata) {
        MHDDaemonWrapper *d = userdata;
        int r;

        assert(d);

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

static int setup_signals(RemoteServer *s) {
        sigset_t mask;
        int r;

        assert(s);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        r = sd_event_add_signal(s->events, &s->sigterm_event, SIGTERM, NULL, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->events, &s->sigint_event, SIGINT, NULL, s);
        if (r < 0)
                return r;

        return 0;
}

static int negative_fd(const char *spec) {
        /* Return a non-positive number as its inverse, -EINVAL otherwise. */

        int fd, r;

        r = safe_atoi(spec, &fd);
        if (r < 0)
                return r;

        if (fd > 0)
                return -EINVAL;
        else
                return -fd;
}

static int remoteserver_init(RemoteServer *s,
                             const char* key,
                             const char* cert,
                             const char* trust) {
        int r, n, fd;
        char **file;

        assert(s);

        if ((arg_listen_raw || arg_listen_http) && trust) {
                log_error("Option --trust makes all non-HTTPS connections untrusted.");
                return -EINVAL;
        }

        r = sd_event_default(&s->events);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        setup_signals(s);

        assert(server == NULL);
        server = s;

        r = init_writer_hashmap(s);
        if (r < 0)
                return r;

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");
        else
                log_debug("Received %d descriptors", n);

        if (MAX(http_socket, https_socket) >= SD_LISTEN_FDS_START + n) {
                log_error("Received fewer sockets than expected");
                return -EBADFD;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                if (sd_is_socket(fd, AF_UNSPEC, 0, true)) {
                        log_debug("Received a listening socket (fd:%d)", fd);

                        if (fd == http_socket)
                                r = setup_microhttpd_server(s, fd, NULL, NULL, NULL);
                        else if (fd == https_socket)
                                r = setup_microhttpd_server(s, fd, key, cert, trust);
                        else
                                r = add_raw_socket(s, fd);
                } else if (sd_is_socket(fd, AF_UNSPEC, 0, false)) {
                        char *hostname;

                        r = getnameinfo_pretty(fd, &hostname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to retrieve remote name: %m");

                        log_debug("Received a connection socket (fd:%d) from %s", fd, hostname);

                        r = add_source(s, fd, hostname, true);
                } else {
                        log_error("Unknown socket passed on fd:%d", fd);

                        return -EINVAL;
                }

                if (r < 0)
                        return log_error_errno(r, "Failed to register socket (fd:%d): %m",
                                               fd);
        }

        if (arg_url) {
                const char *url, *hostname;

                url = strjoina(arg_url, "/entries");

                if (arg_getter) {
                        log_info("Spawning getter %s...", url);
                        fd = spawn_getter(arg_getter, url);
                } else {
                        log_info("Spawning curl %s...", url);
                        fd = spawn_curl(url);
                }
                if (fd < 0)
                        return fd;

                hostname =
                        startswith(arg_url, "https://") ?:
                        startswith(arg_url, "http://") ?:
                        arg_url;

                r = add_source(s, fd, (char*) hostname, false);
                if (r < 0)
                        return r;
        }

        if (arg_listen_raw) {
                log_debug("Listening on a socket...");
                r = setup_raw_socket(s, arg_listen_raw);
                if (r < 0)
                        return r;
        }

        if (arg_listen_http) {
                r = setup_microhttpd_socket(s, arg_listen_http, NULL, NULL, NULL);
                if (r < 0)
                        return r;
        }

        if (arg_listen_https) {
                r = setup_microhttpd_socket(s, arg_listen_https, key, cert, trust);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(file, arg_files) {
                const char *output_name;

                if (streq(*file, "-")) {
                        log_debug("Using standard input as source.");

                        fd = STDIN_FILENO;
                        output_name = "stdin";
                } else {
                        log_debug("Reading file %s...", *file);

                        fd = open(*file, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                        if (fd < 0)
                                return log_error_errno(errno, "Failed to open %s: %m", *file);
                        output_name = *file;
                }

                r = add_source(s, fd, (char*) output_name, false);
                if (r < 0)
                        return r;
        }

        if (s->active == 0) {
                log_error("Zarro sources specified");
                return -EINVAL;
        }

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_NONE) {
                /* In this case we know what the writer will be
                   called, so we can create it and verify that we can
                   create output as expected. */
                r = get_writer(s, NULL, &s->_single_writer);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void server_destroy(RemoteServer *s) {
        size_t i;
        MHDDaemonWrapper *d;

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

        writer_unref(s->_single_writer);
        hashmap_free(s->writers);

        sd_event_source_unref(s->sigterm_event);
        sd_event_source_unref(s->sigint_event);
        sd_event_source_unref(s->listen_event);
        sd_event_unref(s->events);

        /* fds that we're listening on remain open... */
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int handle_raw_source(sd_event_source *event,
                             int fd,
                             uint32_t revents,
                             RemoteServer *s) {

        RemoteSource *source;
        int r;

        /* Returns 1 if there might be more data pending,
         * 0 if data is currently exhausted, negative on error.
         */

        assert(fd >= 0 && fd < (ssize_t) s->sources_size);
        source = s->sources[fd];
        assert(source->fd == fd);

        r = process_source(source, arg_compress, arg_seal);
        if (source->state == STATE_EOF) {
                size_t remaining;

                log_debug("EOF reached with source fd:%d (%s)",
                          source->fd, source->name);

                remaining = source_non_empty(source);
                if (remaining > 0)
                        log_notice("Premature EOF. %zu bytes lost.", remaining);
                remove_source(s, source->fd);
                log_debug("%zu active sources remaining", s->active);
                return 0;
        } else if (r == -E2BIG) {
                log_notice_errno(E2BIG, "Entry too big, skipped");
                return 1;
        } else if (r == -EAGAIN) {
                return 0;
        } else if (r < 0) {
                log_debug_errno(r, "Closing connection: %m");
                remove_source(server, fd);
                return 0;
        } else
                return 1;
}

static int dispatch_raw_source_until_block(sd_event_source *event,
                                           void *userdata) {
        RemoteSource *source = userdata;
        int r;

        /* Make sure event stays around even if source is destroyed */
        sd_event_source_ref(event);

        r = handle_raw_source(event, source->fd, EPOLLIN, server);
        if (r != 1)
                /* No more data for now */
                sd_event_source_set_enabled(event, SD_EVENT_OFF);

        sd_event_source_unref(event);

        return r;
}

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata) {
        RemoteSource *source = userdata;
        int r;

        assert(source->event);
        assert(source->buffer_event);

        r = handle_raw_source(event, fd, EPOLLIN, server);
        if (r == 1)
                /* Might have more data. We need to rerun the handler
                 * until we are sure the buffer is exhausted. */
                sd_event_source_set_enabled(source->buffer_event, SD_EVENT_ON);

        return r;
}

static int dispatch_blocking_source_event(sd_event_source *event,
                                          void *userdata) {
        RemoteSource *source = userdata;

        return handle_raw_source(event, source->fd, EPOLLIN, server);
}

static int accept_connection(const char* type, int fd,
                             SocketAddress *addr, char **hostname) {
        int fd2, r;

        log_debug("Accepting new %s connection on fd:%d", type, fd);
        fd2 = accept4(fd, &addr->sockaddr.sa, &addr->size, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd2 < 0)
                return log_error_errno(errno, "accept() on fd:%d failed: %m", fd);

        switch(socket_address_family(addr)) {
        case AF_INET:
        case AF_INET6: {
                _cleanup_free_ char *a = NULL;
                char *b;

                r = socket_address_print(addr, &a);
                if (r < 0) {
                        log_error_errno(r, "socket_address_print(): %m");
                        close(fd2);
                        return r;
                }

                r = socknameinfo_pretty(&addr->sockaddr, addr->size, &b);
                if (r < 0) {
                        close(fd2);
                        return r;
                }

                log_debug("Accepted %s %s connection from %s",
                          type,
                          socket_address_family(addr) == AF_INET ? "IP" : "IPv6",
                          a);

                *hostname = b;

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
        char *hostname = NULL;

        fd2 = accept_connection("raw", fd, &addr, &hostname);
        if (fd2 < 0)
                return fd2;

        return add_source(s, fd2, hostname, true);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static const char* const journal_write_split_mode_table[_JOURNAL_WRITE_SPLIT_MAX] = {
        [JOURNAL_WRITE_SPLIT_NONE] = "none",
        [JOURNAL_WRITE_SPLIT_HOST] = "host",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(journal_write_split_mode, JournalWriteSplitMode);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_write_split_mode,
                                journal_write_split_mode,
                                JournalWriteSplitMode,
                                "Failed to parse split mode setting");

static int parse_config(void) {
        const ConfigTableItem items[] = {
                { "Remote",  "SplitMode",              config_parse_write_split_mode, 0, &arg_split_mode },
                { "Remote",  "ServerKeyFile",          config_parse_path,             0, &arg_key        },
                { "Remote",  "ServerCertificateFile",  config_parse_path,             0, &arg_cert       },
                { "Remote",  "TrustedCertificateFile", config_parse_path,             0, &arg_trust      },
                {}};

        return config_parse_many(PKGSYSCONFDIR "/journal-remote.conf",
                                 CONF_DIRS_NULSTR("systemd/journal-remote.conf"),
                                 "Remote\0", config_item_table_lookup, items,
                                 false, NULL);
}

static void help(void) {
        printf("%s [OPTIONS...] {FILE|-}...\n\n"
               "Write external journal events to journal file(s).\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --url=URL              Read events from systemd-journal-gatewayd at URL\n"
               "     --getter=COMMAND       Read events from the output of COMMAND\n"
               "     --listen-raw=ADDR      Listen for connections at ADDR\n"
               "     --listen-http=ADDR     Listen for HTTP connections at ADDR\n"
               "     --listen-https=ADDR    Listen for HTTPS connections at ADDR\n"
               "  -o --output=FILE|DIR      Write output to FILE or DIR/external-*.journal\n"
               "     --compress[=BOOL]      XZ-compress the output journal (default: yes)\n"
               "     --seal[=BOOL]          Use event sealing (default: no)\n"
               "     --key=FILENAME         SSL key in PEM format (default:\n"
               "                            \"" PRIV_KEY_FILE "\")\n"
               "     --cert=FILENAME        SSL certificate in PEM format (default:\n"
               "                            \"" CERT_FILE "\")\n"
               "     --trust=FILENAME|all   SSL CA certificate or disable checking (default:\n"
               "                            \"" TRUST_FILE "\")\n"
               "     --gnutls-log=CATEGORY...\n"
               "                            Specify a list of gnutls logging categories\n"
               "     --split-mode=none|host How many output files to create\n"
               "\n"
               "Note: file descriptors from sd_listen_fds() will be consumed, too.\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_URL,
                ARG_LISTEN_RAW,
                ARG_LISTEN_HTTP,
                ARG_LISTEN_HTTPS,
                ARG_GETTER,
                ARG_SPLIT_MODE,
                ARG_COMPRESS,
                ARG_SEAL,
                ARG_KEY,
                ARG_CERT,
                ARG_TRUST,
                ARG_GNUTLS_LOG,
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
                { "split-mode",   required_argument, NULL, ARG_SPLIT_MODE   },
                { "compress",     optional_argument, NULL, ARG_COMPRESS     },
                { "seal",         optional_argument, NULL, ARG_SEAL         },
                { "key",          required_argument, NULL, ARG_KEY          },
                { "cert",         required_argument, NULL, ARG_CERT         },
                { "trust",        required_argument, NULL, ARG_TRUST        },
                { "gnutls-log",   required_argument, NULL, ARG_GNUTLS_LOG   },
                {}
        };

        int c, r;
        bool type_a, type_b;

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

                        r = negative_fd(optarg);
                        if (r >= 0)
                                http_socket = r;
                        else
                                arg_listen_http = optarg;
                        break;

                case ARG_LISTEN_HTTPS:
                        if (arg_listen_https || https_socket >= 0) {
                                log_error("cannot currently use --listen-https more than once");
                                return -EINVAL;
                        }

                        r = negative_fd(optarg);
                        if (r >= 0)
                                https_socket = r;
                        else
                                arg_listen_https = optarg;

                        break;

                case ARG_KEY:
                        if (arg_key) {
                                log_error("Key file specified twice");
                                return -EINVAL;
                        }

                        arg_key = strdup(optarg);
                        if (!arg_key)
                                return log_oom();

                        break;

                case ARG_CERT:
                        if (arg_cert) {
                                log_error("Certificate file specified twice");
                                return -EINVAL;
                        }

                        arg_cert = strdup(optarg);
                        if (!arg_cert)
                                return log_oom();

                        break;

                case ARG_TRUST:
                        if (arg_trust || arg_trust_all) {
                                log_error("Confusing trusted CA configuration");
                                return -EINVAL;
                        }

                        if (streq(optarg, "all"))
                                arg_trust_all = true;
                        else {
#ifdef HAVE_GNUTLS
                                arg_trust = strdup(optarg);
                                if (!arg_trust)
                                        return log_oom();
#else
                                log_error("Option --trust is not available.");
                                return -EINVAL;
#endif
                        }

                        break;

                case 'o':
                        if (arg_output) {
                                log_error("cannot use --output/-o more than once");
                                return -EINVAL;
                        }

                        arg_output = optarg;
                        break;

                case ARG_SPLIT_MODE:
                        arg_split_mode = journal_write_split_mode_from_string(optarg);
                        if (arg_split_mode == _JOURNAL_WRITE_SPLIT_INVALID) {
                                log_error("Invalid split mode: %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_COMPRESS:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse --compress= parameter.");
                                        return -EINVAL;
                                }

                                arg_compress = !!r;
                        } else
                                arg_compress = true;

                        break;

                case ARG_SEAL:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse --seal= parameter.");
                                        return -EINVAL;
                                }

                                arg_seal = !!r;
                        } else
                                arg_seal = true;

                        break;

                case ARG_GNUTLS_LOG: {
#ifdef HAVE_GNUTLS
                        const char *word, *state;
                        size_t size;

                        FOREACH_WORD_SEPARATOR(word, size, optarg, ",", state) {
                                char *cat;

                                cat = strndup(word, size);
                                if (!cat)
                                        return log_oom();

                                if (strv_consume(&arg_gnutls_log, cat) < 0)
                                        return log_oom();
                        }
                        break;
#else
                        log_error("Option --gnutls-log is not available.");
                        return -EINVAL;
#endif
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option code.");
                }

        if (optind < argc)
                arg_files = argv + optind;

        type_a = arg_getter || !strv_isempty(arg_files);
        type_b = arg_url
                || arg_listen_raw
                || arg_listen_http || arg_listen_https
                || sd_listen_fds(false) > 0;
        if (type_a && type_b) {
                log_error("Cannot use file input or --getter with "
                          "--arg-listen-... or socket activation.");
                return -EINVAL;
        }
        if (type_a) {
                if (!arg_output) {
                        log_error("Option --output must be specified with file input or --getter.");
                        return -EINVAL;
                }

                arg_split_mode = JOURNAL_WRITE_SPLIT_NONE;
        }

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_NONE
            && arg_output && is_dir(arg_output, true) > 0) {
                log_error("For SplitMode=none, output must be a file.");
                return -EINVAL;
        }

        if (arg_split_mode == JOURNAL_WRITE_SPLIT_HOST
            && arg_output && is_dir(arg_output, true) <= 0) {
                log_error("For SplitMode=host, output must be a directory.");
                return -EINVAL;
        }

        log_debug("Full config: SplitMode=%s Key=%s Cert=%s Trust=%s",
                  journal_write_split_mode_to_string(arg_split_mode),
                  strna(arg_key),
                  strna(arg_cert),
                  strna(arg_trust));

        return 1 /* work to do */;
}

static int load_certificates(char **key, char **cert, char **trust) {
        int r;

        r = read_full_file(arg_key ?: PRIV_KEY_FILE, key, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read key from file '%s': %m",
                                       arg_key ?: PRIV_KEY_FILE);

        r = read_full_file(arg_cert ?: CERT_FILE, cert, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read certificate from file '%s': %m",
                                       arg_cert ?: CERT_FILE);

        if (arg_trust_all)
                log_info("Certificate checking disabled.");
        else {
                r = read_full_file(arg_trust ?: TRUST_FILE, trust, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read CA certificate file '%s': %m",
                                               arg_trust ?: TRUST_FILE);
        }

        return 0;
}

int main(int argc, char **argv) {
        RemoteServer s = {};
        int r;
        _cleanup_free_ char *key = NULL, *cert = NULL, *trust = NULL;

        log_show_color(true);
        log_parse_environment();

        r = parse_config();
        if (r < 0)
                return EXIT_FAILURE;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;


        if (arg_listen_http || arg_listen_https) {
                r = setup_gnutls_logger(arg_gnutls_log);
                if (r < 0)
                        return EXIT_FAILURE;
        }

        if (arg_listen_https || https_socket >= 0)
                if (load_certificates(&key, &cert, &trust) < 0)
                        return EXIT_FAILURE;

        if (remoteserver_init(&s, key, cert, trust) < 0)
                return EXIT_FAILURE;

        r = sd_event_set_watchdog(s.events, true);
        if (r < 0)
                log_error_errno(r, "Failed to enable watchdog: %m");
        else
                log_debug("Watchdog is %s.", r > 0 ? "enabled" : "disabled");

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
                        log_error_errno(r, "Failed to run event loop: %m");
                        break;
                }
        }

        sd_notifyf(false,
                   "STOPPING=1\n"
                   "STATUS=Shutting down after writing %" PRIu64 " entries...", s.event_count);
        log_info("Finishing after writing %" PRIu64 " entries", s.event_count);

        server_destroy(&s);

        free(arg_key);
        free(arg_cert);
        free(arg_trust);

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
