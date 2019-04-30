/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <stdint.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "def.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "journal-file.h"
#include "journal-remote-write.h"
#include "journal-remote.h"
#include "journald-native.h"
#include "macro.h"
#include "parse-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"

#define REMOTE_JOURNAL_PATH "/var/log/journal/remote"

#define filename_escape(s) xescape((s), "/ ")

static int open_output(RemoteServer *s, Writer *w, const char* host) {
        _cleanup_free_ char *_filename = NULL;
        const char *filename;
        int r;

        switch (s->split_mode) {
        case JOURNAL_WRITE_SPLIT_NONE:
                filename = s->output;
                break;

        case JOURNAL_WRITE_SPLIT_HOST: {
                _cleanup_free_ char *name;

                assert(host);

                name = filename_escape(host);
                if (!name)
                        return log_oom();

                r = asprintf(&_filename, "%s/remote-%s.journal", s->output, name);
                if (r < 0)
                        return log_oom();

                filename = _filename;
                break;
        }

        default:
                assert_not_reached("what?");
        }

        r = journal_file_open_reliably(filename,
                                       O_RDWR|O_CREAT, 0640,
                                       s->compress, (uint64_t) -1, s->seal,
                                       &w->metrics,
                                       w->mmap, NULL,
                                       NULL, &w->journal);
        if (r < 0)
                return log_error_errno(r, "Failed to open output journal %s: %m", filename);

        log_debug("Opened output file %s", w->journal->path);
        return 0;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int init_writer_hashmap(RemoteServer *s) {
        static const struct hash_ops* const hash_ops[] = {
                [JOURNAL_WRITE_SPLIT_NONE] = NULL,
                [JOURNAL_WRITE_SPLIT_HOST] = &string_hash_ops,
        };

        assert(s);
        assert(s->split_mode >= 0 && s->split_mode < (int) ELEMENTSOF(hash_ops));

        s->writers = hashmap_new(hash_ops[s->split_mode]);
        if (!s->writers)
                return log_oom();

        return 0;
}

int journal_remote_get_writer(RemoteServer *s, const char *host, Writer **writer) {
        _cleanup_(writer_unrefp) Writer *w = NULL;
        const void *key;
        int r;

        switch(s->split_mode) {
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

                if (s->split_mode == JOURNAL_WRITE_SPLIT_HOST) {
                        w->hashmap_key = strdup(key);
                        if (!w->hashmap_key)
                                return log_oom();
                }

                r = open_output(s, w, host);
                if (r < 0)
                        return r;

                r = hashmap_put(s->writers, w->hashmap_key ?: key, w);
                if (r < 0)
                        return r;
        }

        *writer = TAKE_PTR(w);

        return 0;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

/* This should go away as soon as µhttpd allows state to be passed around. */
RemoteServer *journal_remote_server_global;

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

static int get_source_for_fd(RemoteServer *s,
                             int fd, char *name, RemoteSource **source) {
        Writer *writer;
        int r;

        /* This takes ownership of name, but only on success. */

        assert(fd >= 0);
        assert(source);

        if (!GREEDY_REALLOC0(s->sources, s->sources_size, fd + 1))
                return log_oom();

        r = journal_remote_get_writer(s, name, &writer);
        if (r < 0)
                return log_warning_errno(r, "Failed to get writer for source %s: %m",
                                         name);

        if (!s->sources[fd]) {
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

int journal_remote_add_source(RemoteServer *s, int fd, char* name, bool own_name) {
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

int journal_remote_add_raw_socket(RemoteServer *s, int fd) {
        int r;
        _cleanup_close_ int fd_ = fd;
        char name[STRLEN("raw-socket-") + DECIMAL_STR_MAX(int) + 1];

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
        s->active++;
        return 0;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

int journal_remote_server_init(
                RemoteServer *s,
                const char *output,
                JournalWriteSplitMode split_mode,
                bool compress,
                bool seal) {

        int r;

        assert(s);

        assert(journal_remote_server_global == NULL);
        journal_remote_server_global = s;

        s->split_mode = split_mode;
        s->compress = compress;
        s->seal = seal;

        if (output)
                s->output = output;
        else if (split_mode == JOURNAL_WRITE_SPLIT_NONE)
                s->output = REMOTE_JOURNAL_PATH "/remote.journal";
        else if (split_mode == JOURNAL_WRITE_SPLIT_HOST)
                s->output = REMOTE_JOURNAL_PATH;
        else
                assert_not_reached("bad split mode");

        r = sd_event_default(&s->events);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = init_writer_hashmap(s);
        if (r < 0)
                return r;

        return 0;
}

#if HAVE_MICROHTTPD
static void MHDDaemonWrapper_free(MHDDaemonWrapper *d) {
        MHD_stop_daemon(d->daemon);
        sd_event_source_unref(d->io_event);
        sd_event_source_unref(d->timer_event);
        free(d);
}
#endif

void journal_remote_server_destroy(RemoteServer *s) {
        size_t i;

#if HAVE_MICROHTTPD
        hashmap_free_with_destructor(s->daemons, MHDDaemonWrapper_free);
#endif

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

        if (s == journal_remote_server_global)
                journal_remote_server_global = NULL;

        /* fds that we're listening on remain open... */
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

int journal_remote_handle_raw_source(
                sd_event_source *event,
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
        assert(source->importer.fd == fd);

        r = process_source(source, s->compress, s->seal);
        if (journal_importer_eof(&source->importer)) {
                size_t remaining;

                log_debug("EOF reached with source %s (fd=%d)",
                          source->importer.name, source->importer.fd);

                remaining = journal_importer_bytes_remaining(&source->importer);
                if (remaining > 0)
                        log_notice("Premature EOF. %zu bytes lost.", remaining);
                remove_source(s, source->importer.fd);
                log_debug("%zu active sources remaining", s->active);
                return 0;
        } else if (r == -E2BIG) {
                log_notice("Entry with too many fields, skipped");
                return 1;
        } else if (r == -ENOBUFS) {
                log_notice("Entry too big, skipped");
                return 1;
        } else if (r == -EAGAIN) {
                return 0;
        } else if (r < 0) {
                log_debug_errno(r, "Closing connection: %m");
                remove_source(s, fd);
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

        r = journal_remote_handle_raw_source(event, source->importer.fd, EPOLLIN, journal_remote_server_global);
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

        r = journal_remote_handle_raw_source(event, fd, EPOLLIN, journal_remote_server_global);
        if (r == 1)
                /* Might have more data. We need to rerun the handler
                 * until we are sure the buffer is exhausted. */
                sd_event_source_set_enabled(source->buffer_event, SD_EVENT_ON);

        return r;
}

static int dispatch_blocking_source_event(sd_event_source *event,
                                          void *userdata) {
        RemoteSource *source = userdata;

        return journal_remote_handle_raw_source(event, source->importer.fd, EPOLLIN, journal_remote_server_global);
}

static int accept_connection(
                const char* type,
                int fd,
                SocketAddress *addr,
                char **hostname) {

        _cleanup_close_ int fd2 = -1;
        int r;

        log_debug("Accepting new %s connection on fd:%d", type, fd);
        fd2 = accept4(fd, &addr->sockaddr.sa, &addr->size, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd2 < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return -EAGAIN;

                return log_error_errno(errno, "accept() on fd:%d failed: %m", fd);
        }

        switch(socket_address_family(addr)) {
        case AF_INET:
        case AF_INET6: {
                _cleanup_free_ char *a = NULL;
                char *b;

                r = socket_address_print(addr, &a);
                if (r < 0)
                        return log_error_errno(r, "socket_address_print(): %m");

                r = socknameinfo_pretty(&addr->sockaddr, addr->size, &b);
                if (r < 0)
                        return log_error_errno(r, "Resolving hostname failed: %m");

                log_debug("Accepted %s %s connection from %s",
                          type,
                          socket_address_family(addr) == AF_INET ? "IP" : "IPv6",
                          a);

                *hostname = b;
                return TAKE_FD(fd2);
        }

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Rejected %s connection with unsupported family %d",
                                       type, socket_address_family(addr));
        }
}

static int dispatch_raw_connection_event(
                sd_event_source *event,
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
        if (fd2 == -EAGAIN)
                return 0;
        if (fd2 < 0)
                return fd2;

        return journal_remote_add_source(s, fd2, hostname, true);
}
