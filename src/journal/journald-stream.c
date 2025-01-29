/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <unistd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "journal-internal.h"
#include "journald-client.h"
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
#include "tmpfile-util.h"
#include "unit-name.h"
#include "user-util.h"

#define STDOUT_STREAMS_MAX (64*1024)

/* During the "setup" protocol phase of the stream logic let's define a different maximum line length than
 * during the actual operational phase. We want to allow users to specify very short line lengths after all,
 * but the unit name we embed in the setup protocol might be longer than that. Hence, during the setup phase
 * let's enforce a line length matching the maximum unit name length (255) */
#define STDOUT_STREAM_SETUP_PROTOCOL_LINE_MAX (UNIT_NAME_MAX-1U)

typedef enum StdoutStreamState {
        STDOUT_STREAM_IDENTIFIER,
        STDOUT_STREAM_UNIT_ID,
        STDOUT_STREAM_PRIORITY,
        STDOUT_STREAM_LEVEL_PREFIX,
        STDOUT_STREAM_FORWARD_TO_SYSLOG,
        STDOUT_STREAM_FORWARD_TO_KMSG,
        STDOUT_STREAM_FORWARD_TO_CONSOLE,
        STDOUT_STREAM_RUNNING,
} StdoutStreamState;

/* The different types of log record terminators: a real \n was read, a NUL character was read, the maximum line length
 * was reached, or the end of the stream was reached */

typedef enum LineBreak {
        LINE_BREAK_NEWLINE,
        LINE_BREAK_NUL,
        LINE_BREAK_LINE_MAX,
        LINE_BREAK_EOF,
        LINE_BREAK_PID_CHANGE,
        _LINE_BREAK_MAX,
        _LINE_BREAK_INVALID = -EINVAL,
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

        sd_event_source *event_source;

        char *state_file;

        ClientContext *context;

        LIST_FIELDS(StdoutStream, stdout_stream);
        LIST_FIELDS(StdoutStream, stdout_stream_notify_queue);

        char id_field[STRLEN("_STREAM_ID=") + SD_ID128_STRING_MAX];
};

StdoutStream* stdout_stream_free(StdoutStream *s) {
        if (!s)
                return NULL;

        if (s->server) {
                if (s->context)
                        client_context_release(s->server, s->context);

                assert(s->server->n_stdout_streams > 0);
                s->server->n_stdout_streams--;
                LIST_REMOVE(stdout_stream, s->server->stdout_streams, s);

                if (s->in_notify_queue)
                        LIST_REMOVE(stdout_stream_notify_queue, s->server->stdout_streams_notify_queue, s);

                (void) server_start_or_stop_idle_timer(s->server); /* Maybe we are idle now? */
        }

        sd_event_source_disable_unref(s->event_source);
        safe_close(s->fd);
        free(s->label);
        free(s->identifier);
        free(s->unit_id);
        free(s->state_file);
        free(s->buffer);

        return mfree(s);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(StdoutStream*, stdout_stream_free);

void stdout_stream_destroy(StdoutStream *s) {
        if (!s)
                return;

        if (s->state_file)
                (void) unlink(s->state_file);

        stdout_stream_free(s);
}

static int stdout_stream_save(StdoutStream *s) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(s);

        if (s->state != STDOUT_STREAM_RUNNING)
                return 0;

        if (!s->state_file) {
                struct stat st;

                r = fstat(s->fd, &st);
                if (r < 0)
                        return log_ratelimit_warning_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to stat connected stream: %m");

                /* We use device and inode numbers as identifier for the stream */
                r = asprintf(&s->state_file, "%s/streams/%lu:%lu", s->server->runtime_directory, (unsigned long) st.st_dev, (unsigned long) st.st_ino);
                if (r < 0)
                        return log_oom();
        }

        (void) mkdir_parents(s->state_file, 0755);

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
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(s->identifier);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "IDENTIFIER=%s\n", escaped);
        }

        if (!isempty(s->unit_id)) {
                _cleanup_free_ char *escaped = NULL;

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

        temp_path = mfree(temp_path);

        if (!s->fdstore && !s->in_notify_queue) {
                LIST_PREPEND(stdout_stream_notify_queue, s->server->stdout_streams_notify_queue, s);
                s->in_notify_queue = true;

                if (s->server->notify_event_source) {
                        r = sd_event_source_set_enabled(s->server->notify_event_source, SD_EVENT_ON);
                        if (r < 0)
                                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to enable notify event source: %m");
                }
        }

        return 0;

fail:
        (void) unlink(s->state_file);
        return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                         "Failed to save stream data %s: %m", s->state_file);
}

static int stdout_stream_log(
                StdoutStream *s,
                const char *p,
                LineBreak line_break) {

        struct iovec *iovec;
        int priority;
        char syslog_priority[] = "PRIORITY=\0";
        char syslog_facility[STRLEN("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_free_ char *message = NULL, *syslog_identifier = NULL;
        size_t n = 0, m;
        int r;

        assert(s);
        assert(p);

        assert(line_break >= 0);
        assert(line_break < _LINE_BREAK_MAX);

        if (s->context)
                (void) client_context_maybe_refresh(s->server, s->context, NULL, NULL, 0, NULL, USEC_INFINITY);
        else if (pid_is_valid(s->ucred.pid)) {
                r = client_context_acquire(s->server, s->ucred.pid, &s->ucred, s->label, strlen_ptr(s->label), s->unit_id, &s->context);
                if (r < 0)
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to acquire client context, ignoring: %m");
        }

        priority = s->priority;

        if (s->level_prefix)
                syslog_parse_priority(&p, &priority, false);

        if (!client_context_test_priority(s->context, priority))
                return 0;

        if (isempty(p))
                return 0;

        r = client_context_check_keep_log(s->context, p, strlen(p));
        if (r <= 0)
                return r;

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

        if (LOG_FAC(priority) != 0) {
                xsprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
                iovec[n++] = IOVEC_MAKE_STRING(syslog_facility);
        }

        if (s->identifier) {
                syslog_identifier = strjoin("SYSLOG_IDENTIFIER=", s->identifier);
                if (syslog_identifier)
                        iovec[n++] = IOVEC_MAKE_STRING(syslog_identifier);
        }

        static const char * const line_break_field_table[_LINE_BREAK_MAX] = {
                [LINE_BREAK_NEWLINE]    = NULL, /* Do not add field if traditional newline */
                [LINE_BREAK_NUL]        = "_LINE_BREAK=nul",
                [LINE_BREAK_LINE_MAX]   = "_LINE_BREAK=line-max",
                [LINE_BREAK_EOF]        = "_LINE_BREAK=eof",
                [LINE_BREAK_PID_CHANGE] = "_LINE_BREAK=pid-change",
        };

        const char *c = line_break_field_table[line_break];

        /* If this log message was generated due to an uncommon line break then mention this in the log
         * entry */
        if (c)
                iovec[n++] = IOVEC_MAKE_STRING(c);

        message = strjoin("MESSAGE=", p);
        if (message)
                iovec[n++] = IOVEC_MAKE_STRING(message);

        server_dispatch_message(s->server, iovec, n, m, s->context, NULL, priority, 0);
        return 0;
}

static int syslog_parse_priority_and_facility(const char *s) {
        int prio, r;

        /* Parses both facility and priority in one value, i.e. is different from log_level_from_string()
         * which only parses the priority and refuses any facility value */

        r = safe_atoi(s, &prio);
        if (r < 0)
                return r;

        if (prio < 0 || prio > 999)
                return -ERANGE;

        return prio;
}

static int stdout_stream_line(StdoutStream *s, char *p, LineBreak line_break) {
        char *orig;
        int r;

        assert(s);
        assert(p);

        orig = p;
        p = strstrip(p);

        /* line breaks by NUL, line max length or EOF are not permissible during the negotiation part of the protocol */
        if (line_break != LINE_BREAK_NEWLINE && s->state != STDOUT_STREAM_RUNNING)
                return log_ratelimit_warning_errno(SYNTHETIC_ERRNO(EINVAL), JOURNAL_LOG_RATELIMIT,
                                                   "Control protocol line not properly terminated.");

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

        case STDOUT_STREAM_PRIORITY: {
                int priority;

                priority = syslog_parse_priority_and_facility(p);
                if (priority < 0)
                        return log_ratelimit_warning_errno(priority, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to parse log priority line: %m");

                s->priority = priority;
                s->state = STDOUT_STREAM_LEVEL_PREFIX;
                return 0;
        }

        case STDOUT_STREAM_LEVEL_PREFIX:
                r = parse_boolean(p);
                if (r < 0)
                        return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to parse level prefix line: %m");

                s->level_prefix = r;
                s->state = STDOUT_STREAM_FORWARD_TO_SYSLOG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_SYSLOG:
                r = parse_boolean(p);
                if (r < 0)
                        return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to parse forward to syslog line: %m");

                s->forward_to_syslog = r;
                s->state = STDOUT_STREAM_FORWARD_TO_KMSG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_KMSG:
                r = parse_boolean(p);
                if (r < 0)
                        return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to parse copy to kmsg line: %m");

                s->forward_to_kmsg = r;
                s->state = STDOUT_STREAM_FORWARD_TO_CONSOLE;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_CONSOLE:
                r = parse_boolean(p);
                if (r < 0)
                        return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                           "Failed to parse copy to console line.");

                s->forward_to_console = r;
                s->state = STDOUT_STREAM_RUNNING;

                /* Try to save the stream, so that journald can be restarted and we can recover */
                (void) stdout_stream_save(s);
                return 0;

        case STDOUT_STREAM_RUNNING:
                return stdout_stream_log(s, orig, line_break);
        }

        assert_not_reached();
}

static int stdout_stream_found(
                StdoutStream *s,
                char *p,
                size_t l,
                LineBreak line_break) {

        char saved;
        int r;

        assert(s);
        assert(p);

        /* Let's NUL terminate the specified buffer for this call, and revert back afterwards */
        saved = p[l];
        p[l] = 0;
        r = stdout_stream_line(s, p, line_break);
        p[l] = saved;

        return r;
}

static size_t stdout_stream_line_max(StdoutStream *s) {
        assert(s);

        /* During the "setup" phase of our protocol, let's ensure we use a line length where a full unit name
         * can fit in */
        if (s->state != STDOUT_STREAM_RUNNING)
                return STDOUT_STREAM_SETUP_PROTOCOL_LINE_MAX;

        /* After the protocol's "setup" phase is complete, let's use whatever the user configured */
        return s->server->line_max;
}

static int stdout_stream_scan(
                StdoutStream *s,
                char *p,
                size_t remaining,
                LineBreak force_flush,
                size_t *ret_consumed) {

        size_t consumed = 0;
        int r;

        assert(s);
        assert(p);

        for (;;) {
                LineBreak line_break;
                size_t skip, found;
                char *end1, *end2;
                size_t tmp_remaining, line_max;

                line_max = stdout_stream_line_max(s);
                tmp_remaining = MIN(remaining, line_max);

                end1 = memchr(p, '\n', tmp_remaining);
                end2 = memchr(p, 0, end1 ? (size_t) (end1 - p) : tmp_remaining);

                if (end2) {
                        /* We found a NUL terminator */
                        found = end2 - p;
                        skip = found + 1;
                        line_break = LINE_BREAK_NUL;
                } else if (end1) {
                        /* We found a \n terminator */
                        found = end1 - p;
                        skip = found + 1;
                        line_break = LINE_BREAK_NEWLINE;
                } else if (remaining >= line_max) {
                        /* Force a line break after the maximum line length */
                        found = skip = line_max;
                        line_break = LINE_BREAK_LINE_MAX;
                } else
                        break;

                r = stdout_stream_found(s, p, found, line_break);
                if (r < 0)
                        return r;

                p += skip;
                consumed += skip;
                remaining -= skip;
        }

        if (force_flush >= 0 && remaining > 0) {
                r = stdout_stream_found(s, p, remaining, force_flush);
                if (r < 0)
                        return r;

                consumed += remaining;
        }

        if (ret_consumed)
                *ret_consumed = consumed;

        return 0;
}

static int stdout_stream_process(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        size_t limit, consumed, allocated;
        StdoutStream *s = ASSERT_PTR(userdata);
        struct ucred *ucred;
        struct iovec iovec;
        ssize_t l;
        char *p;
        int r;

        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        if ((revents|EPOLLIN|EPOLLHUP) != (EPOLLIN|EPOLLHUP)) {
                log_error("Got invalid event from epoll for stdout stream: %"PRIx32, revents);
                goto terminate;
        }

        /* If the buffer is almost full, add room for another 1K */
        allocated = MALLOC_ELEMENTSOF(s->buffer);
        if (s->length + 512 >= allocated) {
                if (!GREEDY_REALLOC(s->buffer, s->length + 1 + 1024)) {
                        log_oom();
                        goto terminate;
                }

                allocated = MALLOC_ELEMENTSOF(s->buffer);
        }

        /* Try to make use of the allocated buffer in full, but never read more than the configured line size. Also,
         * always leave room for a terminating NUL we might need to add. */
        limit = MIN(allocated - 1, MAX(s->server->line_max, STDOUT_STREAM_SETUP_PROTOCOL_LINE_MAX));
        assert(s->length <= limit);
        iovec = IOVEC_MAKE(s->buffer + s->length, limit - s->length);

        l = recvmsg(s->fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                log_ratelimit_warning_errno(errno, JOURNAL_LOG_RATELIMIT, "Failed to read from stream: %m");
                goto terminate;
        }
        cmsg_close_all(&msghdr);

        if (l == 0) {
                (void) stdout_stream_scan(s, s->buffer, s->length, /* force_flush = */ LINE_BREAK_EOF, NULL);
                goto terminate;
        }

        /* Invalidate the context if the PID of the sender changed. This happens when a forked process
         * inherits stdout/stderr from a parent. In this case getpeercred() returns the ucred of the parent,
         * which can be invalid if the parent has exited in the meantime. */
        ucred = CMSG_FIND_DATA(&msghdr, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
        if (ucred && ucred->pid != s->ucred.pid) {
                /* Force out any previously half-written lines from a different process, before we switch to
                 * the new ucred structure for everything we just added */
                r = stdout_stream_scan(s, s->buffer, s->length, /* force_flush = */ LINE_BREAK_PID_CHANGE, NULL);
                if (r < 0)
                        goto terminate;

                s->context = client_context_release(s->server, s->context);

                p = s->buffer + s->length;
        } else {
                p = s->buffer;
                l += s->length;
        }

        /* Always copy in the new credentials */
        if (ucred)
                s->ucred = *ucred;

        r = stdout_stream_scan(s, p, l, _LINE_BREAK_INVALID, &consumed);
        if (r < 0)
                goto terminate;

        /* Move what wasn't consumed to the front of the buffer */
        assert(consumed <= (size_t) l);
        s->length = l - consumed;
        memmove(s->buffer, p + consumed, s->length);

        return 1;

terminate:
        stdout_stream_destroy(s);
        return 0;
}

int stdout_stream_install(Server *s, int fd, StdoutStream **ret) {
        _cleanup_(stdout_stream_freep) StdoutStream *stream = NULL;
        sd_id128_t id;
        int r;

        assert(s);
        assert(fd >= 0);

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to generate stream ID: %m");

        stream = new(StdoutStream, 1);
        if (!stream)
                return log_oom();

        *stream = (StdoutStream) {
                .fd = -EBADF,
                .priority = LOG_INFO,
                .ucred = UCRED_INVALID,
        };

        xsprintf(stream->id_field, "_STREAM_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));

        r = getpeercred(fd, &stream->ucred);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to determine peer credentials: %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

        if (mac_selinux_use()) {
                r = getpeersec(fd, &stream->label);
                if (r < 0 && r != -EOPNOTSUPP)
                        (void) log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to determine peer security context: %m");
        }

        (void) shutdown(fd, SHUT_WR);

        r = sd_event_add_io(s->event, &stream->event_source, fd, EPOLLIN, stdout_stream_process, stream);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to add stream to event loop: %m");

        r = sd_event_source_set_priority(stream->event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to adjust stdout event source priority: %m");

        stream->fd = fd;

        stream->server = s;
        LIST_PREPEND(stdout_stream, s->stdout_streams, stream);
        s->n_stdout_streams++;

        (void) server_start_or_stop_idle_timer(s); /* Maybe no longer idle? */

        if (ret)
                *ret = stream;

        TAKE_PTR(stream);
        return 0;
}

static int stdout_stream_new(sd_event_source *es, int listen_fd, uint32_t revents, void *userdata) {
        _cleanup_close_ int fd = -EBADF;
        Server *s = ASSERT_PTR(userdata);
        int r;

        if (revents != EPOLLIN)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Got invalid event from epoll for stdout server fd: %" PRIx32,
                                       revents);

        fd = accept4(s->stdout_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT, "Failed to accept stdout connection: %m");
        }

        if (s->n_stdout_streams >= STDOUT_STREAMS_MAX) {
                struct ucred u = UCRED_INVALID;

                (void) getpeercred(fd, &u);

                /* By closing fd here we make sure that the client won't wait too long for journald to
                 * gather all the data it adds to the error message to find out that the connection has
                 * just been refused.
                 */
                fd = safe_close(fd);

                server_driver_message(s, u.pid, NULL, LOG_MESSAGE("Too many stdout streams, refusing connection."), NULL);
                return 0;
        }

        r = stdout_stream_install(s, fd, NULL);
        if (r < 0)
                return r;

        TAKE_FD(fd);
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
                stream->state_file = path_join(stream->server->runtime_directory, "streams", fname);
                if (!stream->state_file)
                        return log_oom();
        }

        r = parse_env_file(NULL, stream->state_file,
                           "PRIORITY", &priority,
                           "LEVEL_PREFIX", &level_prefix,
                           "FORWARD_TO_SYSLOG", &forward_to_syslog,
                           "FORWARD_TO_KMSG", &forward_to_kmsg,
                           "FORWARD_TO_CONSOLE", &forward_to_console,
                           "IDENTIFIER", &stream->identifier,
                           "UNIT", &stream->unit_id,
                           "STREAM_ID", &stream_id);
        if (r < 0)
                return log_error_errno(r, "Failed to read: %s", stream->state_file);

        if (priority) {
                int p;

                p = syslog_parse_priority_and_facility(priority);
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
        const char *path;
        int r;

        path = strjoina(s->runtime_directory, "/streams");
        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to enumerate %s: %m", path);
        }

        FOREACH_DIRENT(de, d, goto fail) {
                unsigned long st_dev, st_ino;
                bool found = false;
                int fd;

                if (sscanf(de->d_name, "%lu:%lu", &st_dev, &st_ino) != 2)
                        continue;

                FDSET_FOREACH(fd, fds) {
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
                                log_warning_errno(errno, "Failed to remove %s/%s: %m", path, de->d_name);
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

int server_open_stdout_socket(Server *s, const char *stdout_socket) {
        int r;

        assert(s);
        assert(stdout_socket);

        if (s->stdout_fd < 0) {
                union sockaddr_union sa;
                socklen_t sa_len;

                r = sockaddr_un_set_path(&sa.un, stdout_socket);
                if (r < 0)
                        return log_error_errno(r, "Unable to use namespace path %s for AF_UNIX socket: %m", stdout_socket);
                sa_len = r;

                s->stdout_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->stdout_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                (void) sockaddr_un_unlink(&sa.un);

                r = bind(s->stdout_fd, &sa.sa, sa_len);
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);

                if (listen(s->stdout_fd, SOMAXCONN_DELUXE) < 0)
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
