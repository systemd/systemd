/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <unistd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "journald-console.h"
#include "journald-context.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-stream.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "unit-name.h"

#define STDOUT_STREAMS_MAX 4096

typedef enum StdoutStreamState {
        STDOUT_STREAM_IDENTIFIER,
        STDOUT_STREAM_UNIT_ID,
        STDOUT_STREAM_PRIORITY,
        STDOUT_STREAM_LEVEL_PREFIX,
        STDOUT_STREAM_FORWARD_TO_SYSLOG,
        STDOUT_STREAM_FORWARD_TO_KMSG,
        STDOUT_STREAM_FORWARD_TO_CONSOLE,
        STDOUT_STREAM_RUNNING
} StdoutStreamState;

/* The different types of log record terminators: a real \n was read, a NUL character was read, the maximum line length
 * was reached, or the end of the stream was reached */

typedef enum LineBreak {
        LINE_BREAK_NEWLINE,
        LINE_BREAK_NUL,
        LINE_BREAK_LINE_MAX,
        LINE_BREAK_EOF,
} LineBreak;

struct StdoutStream {
        Server *server;
        StdoutStreamState state;

        int fd;

        struct ucred ucred;
        char *label;
        char *identifier;
        char *unit_id;
        int priority;
        bool level_prefix:1;
        bool forward_to_syslog:1;
        bool forward_to_kmsg:1;
        bool forward_to_console:1;

        bool fdstore:1;
        bool in_notify_queue:1;

        char *buffer;
        size_t length;
        size_t allocated;

        sd_event_source *event_source;

        char *state_file;

        ClientContext *context;

        LIST_FIELDS(StdoutStream, stdout_stream);
        LIST_FIELDS(StdoutStream, stdout_stream_notify_queue);

        char id_field[STRLEN("_STREAM_ID=") + SD_ID128_STRING_MAX];
};

void stdout_stream_free(StdoutStream *s) {
        if (!s)
                return;

        if (s->server) {

                if (s->context)
                        client_context_release(s->server, s->context);

                assert(s->server->n_stdout_streams > 0);
                s->server->n_stdout_streams--;
                LIST_REMOVE(stdout_stream, s->server->stdout_streams, s);

                if (s->in_notify_queue)
                        LIST_REMOVE(stdout_stream_notify_queue, s->server->stdout_streams_notify_queue, s);
        }

        if (s->event_source) {
                sd_event_source_set_enabled(s->event_source, SD_EVENT_OFF);
                s->event_source = sd_event_source_unref(s->event_source);
        }

        safe_close(s->fd);
        free(s->label);
        free(s->identifier);
        free(s->unit_id);
        free(s->state_file);
        free(s->buffer);

        free(s);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(StdoutStream*, stdout_stream_free);

static void stdout_stream_destroy(StdoutStream *s) {
        if (!s)
                return;

        if (s->state_file)
                (void) unlink(s->state_file);

        stdout_stream_free(s);
}

static int stdout_stream_save(StdoutStream *s) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(s);

        if (s->state != STDOUT_STREAM_RUNNING)
                return 0;

        if (!s->state_file) {
                struct stat st;

                r = fstat(s->fd, &st);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to stat connected stream: %m");

                /* We use device and inode numbers as identifier for the stream */
                if (asprintf(&s->state_file, "/run/systemd/journal/streams/%lu:%lu", (unsigned long) st.st_dev, (unsigned long) st.st_ino) < 0)
                        return log_oom();
        }

        mkdir_p("/run/systemd/journal/streams", 0755);

        r = fopen_temporary(s->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        fprintf(f,
                "# This is private data. Do not parse\n"
                "PRIORITY=%i\n"
                "LEVEL_PREFIX=%i\n"
                "FORWARD_TO_SYSLOG=%i\n"
                "FORWARD_TO_KMSG=%i\n"
                "FORWARD_TO_CONSOLE=%i\n"
                "STREAM_ID=%s\n",
                s->priority,
                s->level_prefix,
                s->forward_to_syslog,
                s->forward_to_kmsg,
                s->forward_to_console,
                s->id_field + STRLEN("_STREAM_ID="));

        if (!isempty(s->identifier)) {
                _cleanup_free_ char *escaped;

                escaped = cescape(s->identifier);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "IDENTIFIER=%s\n", escaped);
        }

        if (!isempty(s->unit_id)) {
                _cleanup_free_ char *escaped;

                escaped = cescape(s->unit_id);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "UNIT=%s\n", escaped);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, s->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        if (!s->fdstore && !s->in_notify_queue) {
                LIST_PREPEND(stdout_stream_notify_queue, s->server->stdout_streams_notify_queue, s);
                s->in_notify_queue = true;

                if (s->server->notify_event_source) {
                        r = sd_event_source_set_enabled(s->server->notify_event_source, SD_EVENT_ON);
                        if (r < 0)
                                log_warning_errno(r, "Failed to enable notify event source: %m");
                }
        }

        return 0;

fail:
        (void) unlink(s->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save stream data %s: %m", s->state_file);
}

static int stdout_stream_log(StdoutStream *s, const char *p, LineBreak line_break) {
        struct iovec *iovec;
        int priority;
        char syslog_priority[] = "PRIORITY=\0";
        char syslog_facility[STRLEN("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_free_ char *message = NULL, *syslog_identifier = NULL;
        size_t n = 0, m;
        int r;

        assert(s);
        assert(p);

        if (s->context)
                (void) client_context_maybe_refresh(s->server, s->context, NULL, NULL, 0, NULL, USEC_INFINITY);
        else if (pid_is_valid(s->ucred.pid)) {
                r = client_context_acquire(s->server, s->ucred.pid, &s->ucred, s->label, strlen_ptr(s->label), s->unit_id, &s->context);
                if (r < 0)
                        log_warning_errno(r, "Failed to acquire client context, ignoring: %m");
        }

        priority = s->priority;

        if (s->level_prefix)
                syslog_parse_priority(&p, &priority, false);

        if (!client_context_test_priority(s->context, priority))
                return 0;

        if (isempty(p))
                return 0;

        if (s->forward_to_syslog || s->server->forward_to_syslog)
                server_forward_syslog(s->server, syslog_fixup_facility(priority), s->identifier, p, &s->ucred, NULL);

        if (s->forward_to_kmsg || s->server->forward_to_kmsg)
                server_forward_kmsg(s->server, priority, s->identifier, p, &s->ucred);

        if (s->forward_to_console || s->server->forward_to_console)
                server_forward_console(s->server, priority, s->identifier, p, &s->ucred);

        if (s->server->forward_to_wall)
                server_forward_wall(s->server, priority, s->identifier, p, &s->ucred);

        m = N_IOVEC_META_FIELDS + 7 + client_context_extra_fields_n_iovec(s->context);
        iovec = newa(struct iovec, m);

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=stdout");
        iovec[n++] = IOVEC_MAKE_STRING(s->id_field);

        syslog_priority[STRLEN("PRIORITY=")] = '0' + LOG_PRI(priority);
        iovec[n++] = IOVEC_MAKE_STRING(syslog_priority);

        if (priority & LOG_FACMASK) {
                xsprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                iovec[n++] = IOVEC_MAKE_STRING(syslog_facility);
        }

        if (s->identifier) {
                syslog_identifier = strappend("SYSLOG_IDENTIFIER=", s->identifier);
                if (syslog_identifier)
                        iovec[n++] = IOVEC_MAKE_STRING(syslog_identifier);
        }

        if (line_break != LINE_BREAK_NEWLINE) {
                const char *c;

                /* If this log message was generated due to an uncommon line break then mention this in the log
                 * entry */

                c =     line_break == LINE_BREAK_NUL ?      "_LINE_BREAK=nul" :
                        line_break == LINE_BREAK_LINE_MAX ? "_LINE_BREAK=line-max" :
                                                            "_LINE_BREAK=eof";
                iovec[n++] = IOVEC_MAKE_STRING(c);
        }

        message = strappend("MESSAGE=", p);
        if (message)
                iovec[n++] = IOVEC_MAKE_STRING(message);

        server_dispatch_message(s->server, iovec, n, m, s->context, NULL, priority, 0);
        return 0;
}

static int stdout_stream_line(StdoutStream *s, char *p, LineBreak line_break) {
        int r;
        char *orig;

        assert(s);
        assert(p);

        orig = p;
        p = strstrip(p);

        /* line breaks by NUL, line max length or EOF are not permissible during the negotiation part of the protocol */
        if (line_break != LINE_BREAK_NEWLINE && s->state != STDOUT_STREAM_RUNNING) {
                log_warning("Control protocol line not properly terminated.");
                return -EINVAL;
        }

        switch (s->state) {

        case STDOUT_STREAM_IDENTIFIER:
                if (!isempty(p)) {
                        s->identifier = strdup(p);
                        if (!s->identifier)
                                return log_oom();
                }

                s->state = STDOUT_STREAM_UNIT_ID;
                return 0;

        case STDOUT_STREAM_UNIT_ID:
                if (s->ucred.uid == 0 &&
                    unit_name_is_valid(p, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {

                        s->unit_id = strdup(p);
                        if (!s->unit_id)
                                return log_oom();
                }

                s->state = STDOUT_STREAM_PRIORITY;
                return 0;

        case STDOUT_STREAM_PRIORITY:
                r = safe_atoi(p, &s->priority);
                if (r < 0 || s->priority < 0 || s->priority > 999) {
                        log_warning("Failed to parse log priority line.");
                        return -EINVAL;
                }

                s->state = STDOUT_STREAM_LEVEL_PREFIX;
                return 0;

        case STDOUT_STREAM_LEVEL_PREFIX:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse level prefix line.");
                        return -EINVAL;
                }

                s->level_prefix = r;
                s->state = STDOUT_STREAM_FORWARD_TO_SYSLOG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_SYSLOG:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse forward to syslog line.");
                        return -EINVAL;
                }

                s->forward_to_syslog = r;
                s->state = STDOUT_STREAM_FORWARD_TO_KMSG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_KMSG:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse copy to kmsg line.");
                        return -EINVAL;
                }

                s->forward_to_kmsg = r;
                s->state = STDOUT_STREAM_FORWARD_TO_CONSOLE;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_CONSOLE:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse copy to console line.");
                        return -EINVAL;
                }

                s->forward_to_console = r;
                s->state = STDOUT_STREAM_RUNNING;

                /* Try to save the stream, so that journald can be restarted and we can recover */
                (void) stdout_stream_save(s);
                return 0;

        case STDOUT_STREAM_RUNNING:
                return stdout_stream_log(s, orig, line_break);
        }

        assert_not_reached("Unknown stream state");
}

static int stdout_stream_scan(StdoutStream *s, bool force_flush) {
        char *p;
        size_t remaining;
        int r;

        assert(s);

        p = s->buffer;
        remaining = s->length;

        /* XXX: This function does nothing if (s->length == 0) */

        for (;;) {
                LineBreak line_break;
                size_t skip;
                char *end1, *end2;

                end1 = memchr(p, '\n', remaining);
                end2 = memchr(p, 0, end1 ? (size_t) (end1 - p) : remaining);

                if (end2) {
                        /* We found a NUL terminator */
                        skip = end2 - p + 1;
                        line_break = LINE_BREAK_NUL;
                } else if (end1) {
                        /* We found a \n terminator */
                        *end1 = 0;
                        skip = end1 - p + 1;
                        line_break = LINE_BREAK_NEWLINE;
                } else if (remaining >= s->server->line_max) {
                        /* Force a line break after the maximum line length */
                        *(p + s->server->line_max) = 0;
                        skip = remaining;
                        line_break = LINE_BREAK_LINE_MAX;
                } else
                        break;

                r = stdout_stream_line(s, p, line_break);
                if (r < 0)
                        return r;

                remaining -= skip;
                p += skip;
        }

        if (force_flush && remaining > 0) {
                p[remaining] = 0;
                r = stdout_stream_line(s, p, LINE_BREAK_EOF);
                if (r < 0)
                        return r;

                p += remaining;
                remaining = 0;
        }

        if (p > s->buffer) {
                memmove(s->buffer, p, remaining);
                s->length = remaining;
        }

        return 0;
}

static int stdout_stream_process(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        StdoutStream *s = userdata;
        size_t limit;
        ssize_t l;
        int r;

        assert(s);

        if ((revents|EPOLLIN|EPOLLHUP) != (EPOLLIN|EPOLLHUP)) {
                log_error("Got invalid event from epoll for stdout stream: %"PRIx32, revents);
                goto terminate;
        }

        /* If the buffer is full already (discounting the extra NUL we need), add room for another 1K */
        if (s->length + 1 >= s->allocated) {
                if (!GREEDY_REALLOC(s->buffer, s->allocated, s->length + 1 + 1024)) {
                        log_oom();
                        goto terminate;
                }
        }

        /* Try to make use of the allocated buffer in full, but never read more than the configured line size. Also,
         * always leave room for a terminating NUL we might need to add. */
        limit = MIN(s->allocated - 1, s->server->line_max);

        l = read(s->fd, s->buffer + s->length, limit - s->length);
        if (l < 0) {
                if (errno == EAGAIN)
                        return 0;

                log_warning_errno(errno, "Failed to read from stream: %m");
                goto terminate;
        }

        if (l == 0) {
                stdout_stream_scan(s, true);
                goto terminate;
        }

        s->length += l;
        r = stdout_stream_scan(s, false);
        if (r < 0)
                goto terminate;

        return 1;

terminate:
        stdout_stream_destroy(s);
        return 0;
}

static int stdout_stream_install(Server *s, int fd, StdoutStream **ret) {
        _cleanup_(stdout_stream_freep) StdoutStream *stream = NULL;
        sd_id128_t id;
        int r;

        assert(s);
        assert(fd >= 0);

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate stream ID: %m");

        stream = new0(StdoutStream, 1);
        if (!stream)
                return log_oom();

        stream->fd = -1;
        stream->priority = LOG_INFO;

        xsprintf(stream->id_field, "_STREAM_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));

        r = getpeercred(fd, &stream->ucred);
        if (r < 0)
                return log_error_errno(r, "Failed to determine peer credentials: %m");

        if (mac_selinux_use()) {
                r = getpeersec(fd, &stream->label);
                if (r < 0 && r != -EOPNOTSUPP)
                        (void) log_warning_errno(r, "Failed to determine peer security context: %m");
        }

        (void) shutdown(fd, SHUT_WR);

        r = sd_event_add_io(s->event, &stream->event_source, fd, EPOLLIN, stdout_stream_process, stream);
        if (r < 0)
                return log_error_errno(r, "Failed to add stream to event loop: %m");

        r = sd_event_source_set_priority(stream->event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust stdout event source priority: %m");

        stream->fd = fd;

        stream->server = s;
        LIST_PREPEND(stdout_stream, s->stdout_streams, stream);
        s->n_stdout_streams++;

        if (ret)
                *ret = stream;

        stream = NULL;

        return 0;
}

static int stdout_stream_new(sd_event_source *es, int listen_fd, uint32_t revents, void *userdata) {
        _cleanup_close_ int fd = -1;
        Server *s = userdata;
        int r;

        assert(s);

        if (revents != EPOLLIN) {
                log_error("Got invalid event from epoll for stdout server fd: %"PRIx32, revents);
                return -EIO;
        }

        fd = accept4(s->stdout_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd < 0) {
                if (errno == EAGAIN)
                        return 0;

                return log_error_errno(errno, "Failed to accept stdout connection: %m");
        }

        if (s->n_stdout_streams >= STDOUT_STREAMS_MAX) {
                struct ucred u;

                r = getpeercred(fd, &u);

                /* By closing fd here we make sure that the client won't wait too long for journald to
                 * gather all the data it adds to the error message to find out that the connection has
                 * just been refused.
                 */
                fd = safe_close(fd);

                server_driver_message(s, r < 0 ? 0 : u.pid, NULL, LOG_MESSAGE("Too many stdout streams, refusing connection."), NULL);
                return 0;
        }

        r = stdout_stream_install(s, fd, NULL);
        if (r < 0)
                return r;

        fd = -1;
        return 0;
}

static int stdout_stream_load(StdoutStream *stream, const char *fname) {
        _cleanup_free_ char
                *priority = NULL,
                *level_prefix = NULL,
                *forward_to_syslog = NULL,
                *forward_to_kmsg = NULL,
                *forward_to_console = NULL,
                *stream_id = NULL;
        int r;

        assert(stream);
        assert(fname);

        if (!stream->state_file) {
                stream->state_file = strappend("/run/systemd/journal/streams/", fname);
                if (!stream->state_file)
                        return log_oom();
        }

        r = parse_env_file(NULL, stream->state_file, NEWLINE,
                           "PRIORITY", &priority,
                           "LEVEL_PREFIX", &level_prefix,
                           "FORWARD_TO_SYSLOG", &forward_to_syslog,
                           "FORWARD_TO_KMSG", &forward_to_kmsg,
                           "FORWARD_TO_CONSOLE", &forward_to_console,
                           "IDENTIFIER", &stream->identifier,
                           "UNIT", &stream->unit_id,
                           "STREAM_ID", &stream_id,
                           NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read: %s", stream->state_file);

        if (priority) {
                int p;

                p = log_level_from_string(priority);
                if (p >= 0)
                        stream->priority = p;
        }

        if (level_prefix) {
                r = parse_boolean(level_prefix);
                if (r >= 0)
                        stream->level_prefix = r;
        }

        if (forward_to_syslog) {
                r = parse_boolean(forward_to_syslog);
                if (r >= 0)
                        stream->forward_to_syslog = r;
        }

        if (forward_to_kmsg) {
                r = parse_boolean(forward_to_kmsg);
                if (r >= 0)
                        stream->forward_to_kmsg = r;
        }

        if (forward_to_console) {
                r = parse_boolean(forward_to_console);
                if (r >= 0)
                        stream->forward_to_console = r;
        }

        if (stream_id) {
                sd_id128_t id;

                r = sd_id128_from_string(stream_id, &id);
                if (r >= 0)
                        xsprintf(stream->id_field, "_STREAM_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
        }

        return 0;
}

static int stdout_stream_restore(Server *s, const char *fname, int fd) {
        StdoutStream *stream;
        int r;

        assert(s);
        assert(fname);
        assert(fd >= 0);

        if (s->n_stdout_streams >= STDOUT_STREAMS_MAX) {
                log_warning("Too many stdout streams, refusing restoring of stream.");
                return -ENOBUFS;
        }

        r = stdout_stream_install(s, fd, &stream);
        if (r < 0)
                return r;

        stream->state = STDOUT_STREAM_RUNNING;
        stream->fdstore = true;

        /* Ignore all parsing errors */
        (void) stdout_stream_load(stream, fname);

        return 0;
}

int server_restore_streams(Server *s, FDSet *fds) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        d = opendir("/run/systemd/journal/streams");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to enumerate /run/systemd/journal/streams: %m");
        }

        FOREACH_DIRENT(de, d, goto fail) {
                unsigned long st_dev, st_ino;
                bool found = false;
                Iterator i;
                int fd;

                if (sscanf(de->d_name, "%lu:%lu", &st_dev, &st_ino) != 2)
                        continue;

                FDSET_FOREACH(fd, fds, i) {
                        struct stat st;

                        if (fstat(fd, &st) < 0)
                                return log_error_errno(errno, "Failed to stat %s: %m", de->d_name);

                        if (S_ISSOCK(st.st_mode) && st.st_dev == st_dev && st.st_ino == st_ino) {
                                found = true;
                                break;
                        }
                }

                if (!found) {
                        /* No file descriptor? Then let's delete the state file */
                        log_debug("Cannot restore stream file %s", de->d_name);
                        if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                                log_warning_errno(errno, "Failed to remove /run/systemd/journal/streams/%s: %m",
                                                  de->d_name);
                        continue;
                }

                fdset_remove(fds, fd);

                r = stdout_stream_restore(s, de->d_name, fd);
                if (r < 0)
                        safe_close(fd);
        }

        return 0;

fail:
        return log_error_errno(errno, "Failed to read streams directory: %m");
}

int server_open_stdout_socket(Server *s) {
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/stdout",
        };
        int r;

        assert(s);

        if (s->stdout_fd < 0) {
                s->stdout_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->stdout_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                (void) sockaddr_un_unlink(&sa.un);

                r = bind(s->stdout_fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);

                if (listen(s->stdout_fd, SOMAXCONN) < 0)
                        return log_error_errno(errno, "listen(%s) failed: %m", sa.un.sun_path);
        } else
                (void) fd_nonblock(s->stdout_fd, true);

        r = sd_event_add_io(s->event, &s->stdout_event_source, s->stdout_fd, EPOLLIN, stdout_stream_new, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add stdout server fd to event source: %m");

        r = sd_event_source_set_priority(s->stdout_event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust priority of stdout server event source: %m");

        return 0;
}

void stdout_stream_send_notify(StdoutStream *s) {
        struct iovec iovec = {
                .iov_base = (char*) "FDSTORE=1",
                .iov_len = STRLEN("FDSTORE=1"),
        };
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
        };
        struct cmsghdr *cmsg;
        ssize_t l;

        assert(s);
        assert(!s->fdstore);
        assert(s->in_notify_queue);
        assert(s->server);
        assert(s->server->notify_fd >= 0);

        /* Store the connection fd in PID 1, so that we get it passed
         * in again on next start */

        msghdr.msg_controllen = CMSG_SPACE(sizeof(int));
        msghdr.msg_control = alloca0(msghdr.msg_controllen);

        cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        memcpy(CMSG_DATA(cmsg), &s->fd, sizeof(int));

        l = sendmsg(s->server->notify_fd, &msghdr, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (l < 0) {
                if (errno == EAGAIN)
                        return;

                log_error_errno(errno, "Failed to send stream file descriptor to service manager: %m");
        } else {
                log_debug("Successfully sent stream file descriptor to service manager.");
                s->fdstore = 1;
        }

        LIST_REMOVE(stdout_stream_notify_queue, s->server->stdout_streams_notify_queue, s);
        s->in_notify_queue = false;

}
