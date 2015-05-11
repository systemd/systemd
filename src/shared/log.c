/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <printf.h>

#include "sd-messages.h"
#include "log.h"
#include "util.h"
#include "missing.h"
#include "macro.h"
#include "socket-util.h"
#include "formats-util.h"
#include "process-util.h"
#include "terminal-util.h"

#define SNDBUF_SIZE (8*1024*1024)

static LogTarget log_target = LOG_TARGET_CONSOLE;
static int log_max_level = LOG_INFO;
static int log_facility = LOG_DAEMON;

static int console_fd = STDERR_FILENO;
static int syslog_fd = -1;
static int kmsg_fd = -1;
static int journal_fd = -1;

static bool syslog_is_stream = false;

static bool show_color = false;
static bool show_location = false;

static bool upgrade_syslog_to_journal = false;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char *log_abort_msg = NULL;

void log_close_console(void) {

        if (console_fd < 0)
                return;

        if (getpid() == 1) {
                if (console_fd >= 3)
                        safe_close(console_fd);

                console_fd = -1;
        }
}

static int log_open_console(void) {

        if (console_fd >= 0)
                return 0;

        if (getpid() == 1) {
                console_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (console_fd < 0)
                        return console_fd;
        } else
                console_fd = STDERR_FILENO;

        return 0;
}

void log_close_kmsg(void) {
        kmsg_fd = safe_close(kmsg_fd);
}

static int log_open_kmsg(void) {

        if (kmsg_fd >= 0)
                return 0;

        kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (kmsg_fd < 0)
                return -errno;

        return 0;
}

void log_close_syslog(void) {
        syslog_fd = safe_close(syslog_fd);
}

static int create_log_socket(int type) {
        struct timeval tv;
        int fd;

        fd = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        /* We need a blocking fd here since we'd otherwise lose
        messages way too early. However, let's not hang forever in the
        unlikely case of a deadlock. */
        if (getpid() == 1)
                timeval_store(&tv, 10 * USEC_PER_MSEC);
        else
                timeval_store(&tv, 10 * USEC_PER_SEC);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return fd;
}

static int log_open_syslog(void) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/dev/log",
        };

        int r;

        if (syslog_fd >= 0)
                return 0;

        syslog_fd = create_log_socket(SOCK_DGRAM);
        if (syslog_fd < 0) {
                r = syslog_fd;
                goto fail;
        }

        if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                safe_close(syslog_fd);

                /* Some legacy syslog systems still use stream
                 * sockets. They really shouldn't. But what can we
                 * do... */
                syslog_fd = create_log_socket(SOCK_STREAM);
                if (syslog_fd < 0) {
                        r = syslog_fd;
                        goto fail;
                }

                if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                        r = -errno;
                        goto fail;
                }

                syslog_is_stream = true;
        } else
                syslog_is_stream = false;

        return 0;

fail:
        log_close_syslog();
        return r;
}

void log_close_journal(void) {
        journal_fd = safe_close(journal_fd);
}

static int log_open_journal(void) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/socket",
        };

        int r;

        if (journal_fd >= 0)
                return 0;

        journal_fd = create_log_socket(SOCK_DGRAM);
        if (journal_fd < 0) {
                r = journal_fd;
                goto fail;
        }

        if (connect(journal_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        log_close_journal();
        return r;
}

int log_open(void) {
        int r;

        /* If we don't use the console we close it here, to not get
         * killed by SAK. If we don't use syslog we close it here so
         * that we are not confused by somebody deleting the socket in
         * the fs. If we don't use /dev/kmsg we still keep it open,
         * because there is no reason to close it. */

        if (log_target == LOG_TARGET_NULL) {
                log_close_journal();
                log_close_syslog();
                log_close_console();
                return 0;
        }

        if ((log_target != LOG_TARGET_AUTO && log_target != LOG_TARGET_SAFE) ||
            getpid() == 1 ||
            isatty(STDERR_FILENO) <= 0) {

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_JOURNAL) {
                        r = log_open_journal();
                        if (r >= 0) {
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {
                        r = log_open_syslog();
                        if (r >= 0) {
                                log_close_journal();
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_SAFE ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_KMSG) {
                        r = log_open_kmsg();
                        if (r >= 0) {
                                log_close_journal();
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }
        }

        log_close_journal();
        log_close_syslog();

        return log_open_console();
}

void log_set_target(LogTarget target) {
        assert(target >= 0);
        assert(target < _LOG_TARGET_MAX);

        if (upgrade_syslog_to_journal) {
                if (target == LOG_TARGET_SYSLOG)
                        target = LOG_TARGET_JOURNAL;
                else if (target == LOG_TARGET_SYSLOG_OR_KMSG)
                        target = LOG_TARGET_JOURNAL_OR_KMSG;
        }

        log_target = target;
}

void log_close(void) {
        log_close_journal();
        log_close_syslog();
        log_close_kmsg();
        log_close_console();
}

void log_forget_fds(void) {
        console_fd = kmsg_fd = syslog_fd = journal_fd = -1;
}

void log_set_max_level(int level) {
        assert((level & LOG_PRIMASK) == level);

        log_max_level = level;
}

void log_set_facility(int facility) {
        log_facility = facility;
}

static int write_to_console(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *buffer) {

        char location[64], prefix[1 + DECIMAL_STR_MAX(int) + 2];
        struct iovec iovec[6] = {};
        unsigned n = 0;
        bool highlight;

        if (console_fd < 0)
                return 0;

        if (log_target == LOG_TARGET_CONSOLE_PREFIXED) {
                sprintf(prefix, "<%i>", level);
                IOVEC_SET_STRING(iovec[n++], prefix);
        }

        highlight = LOG_PRI(level) <= LOG_ERR && show_color;

        if (show_location) {
                snprintf(location, sizeof(location), "(%s:%i) ", file, line);
                IOVEC_SET_STRING(iovec[n++], location);
        }

        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_RED_ON);
        IOVEC_SET_STRING(iovec[n++], buffer);
        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_OFF);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(console_fd, iovec, n) < 0) {

                if (errno == EIO && getpid() == 1) {

                        /* If somebody tried to kick us from our
                         * console tty (via vhangup() or suchlike),
                         * try to reconnect */

                        log_close_console();
                        log_open_console();

                        if (console_fd < 0)
                                return 0;

                        if (writev(console_fd, iovec, n) < 0)
                                return -errno;
                } else
                        return -errno;
        }

        return 1;
}

static int write_to_syslog(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *buffer) {

        char header_priority[2 + DECIMAL_STR_MAX(int) + 1],
             header_time[64],
             header_pid[4 + DECIMAL_STR_MAX(pid_t) + 1];
        struct iovec iovec[5] = {};
        struct msghdr msghdr = {
                .msg_iov = iovec,
                .msg_iovlen = ELEMENTSOF(iovec),
        };
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return 0;

        xsprintf(header_priority, "<%i>", level);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        tm = localtime(&t);
        if (!tm)
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        xsprintf(header_pid, "["PID_FMT"]: ", getpid());

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        /* When using syslog via SOCK_STREAM separate the messages by NUL chars */
        if (syslog_is_stream)
                iovec[4].iov_len++;

        for (;;) {
                ssize_t n;

                n = sendmsg(syslog_fd, &msghdr, MSG_NOSIGNAL);
                if (n < 0)
                        return -errno;

                if (!syslog_is_stream ||
                    (size_t) n >= IOVEC_TOTAL_SIZE(iovec, ELEMENTSOF(iovec)))
                        break;

                IOVEC_INCREMENT(iovec, ELEMENTSOF(iovec), n);
        }

        return 1;
}

static int write_to_kmsg(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *buffer) {

        char header_priority[2 + DECIMAL_STR_MAX(int) + 1],
             header_pid[4 + DECIMAL_STR_MAX(pid_t) + 1];
        struct iovec iovec[5] = {};

        if (kmsg_fd < 0)
                return 0;

        xsprintf(header_priority, "<%i>", level);
        xsprintf(header_pid, "["PID_FMT"]: ", getpid());

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], "\n");

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 1;
}

static int log_do_header(
                char *header,
                size_t size,
                int level,
                int error,
                const char *file, int line, const char *func,
                const char *object_field, const char *object) {

        snprintf(header, size,
                 "PRIORITY=%i\n"
                 "SYSLOG_FACILITY=%i\n"
                 "%s%s%s"
                 "%s%.*i%s"
                 "%s%s%s"
                 "%s%.*i%s"
                 "%s%s%s"
                 "SYSLOG_IDENTIFIER=%s\n",
                 LOG_PRI(level),
                 LOG_FAC(level),
                 isempty(file) ? "" : "CODE_FILE=",
                 isempty(file) ? "" : file,
                 isempty(file) ? "" : "\n",
                 line ? "CODE_LINE=" : "",
                 line ? 1 : 0, line, /* %.0d means no output too, special case for 0 */
                 line ? "\n" : "",
                 isempty(func) ? "" : "CODE_FUNCTION=",
                 isempty(func) ? "" : func,
                 isempty(func) ? "" : "\n",
                 error ? "ERRNO=" : "",
                 error ? 1 : 0, error,
                 error ? "\n" : "",
                 isempty(object) ? "" : object_field,
                 isempty(object) ? "" : object,
                 isempty(object) ? "" : "\n",
                 program_invocation_short_name);

        return 0;
}

static int write_to_journal(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *buffer) {

        char header[LINE_MAX];
        struct iovec iovec[4] = {};
        struct msghdr mh = {};

        if (journal_fd < 0)
                return 0;

        log_do_header(header, sizeof(header), level, error, file, line, func, object_field, object);

        IOVEC_SET_STRING(iovec[0], header);
        IOVEC_SET_STRING(iovec[1], "MESSAGE=");
        IOVEC_SET_STRING(iovec[2], buffer);
        IOVEC_SET_STRING(iovec[3], "\n");

        mh.msg_iov = iovec;
        mh.msg_iovlen = ELEMENTSOF(iovec);

        if (sendmsg(journal_fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 1;
}

static int log_dispatch(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                char *buffer) {

        assert(buffer);

        if (log_target == LOG_TARGET_NULL)
                return -error;

        /* Patch in LOG_DAEMON facility if necessary */
        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);

        if (error < 0)
                error = -error;

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_JOURNAL) {

                        k = write_to_journal(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_journal();
                                log_open_kmsg();
                        }
                }

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {

                        k = write_to_syslog(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_syslog();
                                log_open_kmsg();
                        }
                }

                if (k <= 0 &&
                    (log_target == LOG_TARGET_AUTO ||
                     log_target == LOG_TARGET_SAFE ||
                     log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                     log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                     log_target == LOG_TARGET_KMSG)) {

                        k = write_to_kmsg(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                log_close_kmsg();
                                log_open_console();
                        }
                }

                if (k <= 0)
                        (void) write_to_console(level, error, file, line, func, object_field, object, buffer);

                buffer = e;
        } while (buffer);

        return -error;
}

int log_dump_internal(
        int level,
        int error,
        const char *file,
        int line,
        const char *func,
        char *buffer) {

        PROTECT_ERRNO;

        /* This modifies the buffer... */

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        return log_dispatch(level, error, file, line, func, NULL, NULL, buffer);
}

int log_internalv(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *format,
                va_list ap) {

        PROTECT_ERRNO;
        char buffer[LINE_MAX];

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        /* Make sure that %m maps to the specified error */
        if (error != 0)
                errno = error;

        vsnprintf(buffer, sizeof(buffer), format, ap);

        return log_dispatch(level, error, file, line, func, NULL, NULL, buffer);
}

int log_internal(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *format, ...) {

        va_list ap;
        int r;

        va_start(ap, format);
        r = log_internalv(level, error, file, line, func, format, ap);
        va_end(ap);

        return r;
}

int log_object_internalv(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *format,
                va_list ap) {

        PROTECT_ERRNO;
        char *buffer, *b;
        size_t l;

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        /* Make sure that %m maps to the specified error */
        if (error != 0)
                errno = error;

        /* Prepend the object name before the message */
        if (object) {
                size_t n;

                n = strlen(object);
                l = n + 2 + LINE_MAX;

                buffer = newa(char, l);
                b = stpcpy(stpcpy(buffer, object), ": ");
        } else {
                l = LINE_MAX;
                b = buffer = newa(char, l);
        }

        vsnprintf(b, l, format, ap);

        return log_dispatch(level, error, file, line, func, object_field, object, buffer);
}

int log_object_internal(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *format, ...) {

        va_list ap;
        int r;

        va_start(ap, format);
        r = log_object_internalv(level, error, file, line, func, object_field, object, format, ap);
        va_end(ap);

        return r;
}

static void log_assert(
                int level,
                const char *text,
                const char *file,
                int line,
                const char *func,
                const char *format) {

        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_max_level))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        snprintf(buffer, sizeof(buffer), format, text, file, line, func);
        REENABLE_WARNING;

        log_abort_msg = buffer;

        log_dispatch(level, 0, file, line, func, NULL, NULL, buffer);
}

noreturn void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
        abort();
}

noreturn void log_assert_failed_unreachable(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Code should not be reached '%s' at %s:%u, function %s(). Aborting.");
        abort();
}

void log_assert_failed_return(const char *text, const char *file, int line, const char *func) {
        PROTECT_ERRNO;
        log_assert(LOG_DEBUG, text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Ignoring.");
}

int log_oom_internal(const char *file, int line, const char *func) {
        log_internal(LOG_ERR, ENOMEM, file, line, func, "Out of memory.");
        return -ENOMEM;
}

int log_struct_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) {

        char buf[LINE_MAX];
        bool found = false;
        PROTECT_ERRNO;
        va_list ap;

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        if (log_target == LOG_TARGET_NULL)
                return -error;

        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);

        if ((log_target == LOG_TARGET_AUTO ||
             log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
             log_target == LOG_TARGET_JOURNAL) &&
            journal_fd >= 0) {
                char header[LINE_MAX];
                struct iovec iovec[17] = {};
                unsigned n = 0, i;
                struct msghdr mh = {
                        .msg_iov = iovec,
                };
                static const char nl = '\n';
                bool fallback = false;

                /* If the journal is available do structured logging */
                log_do_header(header, sizeof(header), level, error, file, line, func, NULL, NULL);
                IOVEC_SET_STRING(iovec[n++], header);

                va_start(ap, format);
                while (format && n + 1 < ELEMENTSOF(iovec)) {
                        va_list aq;
                        char *m;

                        /* We need to copy the va_list structure,
                         * since vasprintf() leaves it afterwards at
                         * an undefined location */

                        if (error != 0)
                                errno = error;

                        va_copy(aq, ap);
                        if (vasprintf(&m, format, aq) < 0) {
                                va_end(aq);
                                fallback = true;
                                goto finish;
                        }
                        va_end(aq);

                        /* Now, jump enough ahead, so that we point to
                         * the next format string */
                        VA_FORMAT_ADVANCE(format, ap);

                        IOVEC_SET_STRING(iovec[n++], m);

                        iovec[n].iov_base = (char*) &nl;
                        iovec[n].iov_len = 1;
                        n++;

                        format = va_arg(ap, char *);
                }

                mh.msg_iovlen = n;

                (void) sendmsg(journal_fd, &mh, MSG_NOSIGNAL);

        finish:
                va_end(ap);
                for (i = 1; i < n; i += 2)
                        free(iovec[i].iov_base);

                if (!fallback)
                        return -error;
        }

        /* Fallback if journal logging is not available or didn't work. */

        va_start(ap, format);
        while (format) {
                va_list aq;

                if (error != 0)
                        errno = error;

                va_copy(aq, ap);
                vsnprintf(buf, sizeof(buf), format, aq);
                va_end(aq);

                if (startswith(buf, "MESSAGE=")) {
                        found = true;
                        break;
                }

                VA_FORMAT_ADVANCE(format, ap);

                format = va_arg(ap, char *);
        }
        va_end(ap);

        if (!found)
                return -error;

        return log_dispatch(level, error, file, line, func, NULL, NULL, buf + 8);
}

int log_set_target_from_string(const char *e) {
        LogTarget t;

        t = log_target_from_string(e);
        if (t < 0)
                return -EINVAL;

        log_set_target(t);
        return 0;
}

int log_set_max_level_from_string(const char *e) {
        int t;

        t = log_level_from_string(e);
        if (t < 0)
                return t;

        log_set_max_level(t);
        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value) {

        /*
         * The systemd.log_xyz= settings are parsed by all tools, and
         * so is "debug".
         *
         * However, "quiet" is only parsed by PID 1, and only turns of
         * status output to /dev/console, but does not alter the log
         * level.
         */

        if (streq(key, "debug") && !value)
                log_set_max_level(LOG_DEBUG);

        else if (streq(key, "systemd.log_target") && value) {

                if (log_set_target_from_string(value) < 0)
                        log_warning("Failed to parse log target '%s'. Ignoring.", value);

        } else if (streq(key, "systemd.log_level") && value) {

                if (log_set_max_level_from_string(value) < 0)
                        log_warning("Failed to parse log level '%s'. Ignoring.", value);

        } else if (streq(key, "systemd.log_color") && value) {

                if (log_show_color_from_string(value) < 0)
                        log_warning("Failed to parse log color setting '%s'. Ignoring.", value);

        } else if (streq(key, "systemd.log_location") && value) {

                if (log_show_location_from_string(value) < 0)
                        log_warning("Failed to parse log location setting '%s'. Ignoring.", value);
        }

        return 0;
}

void log_parse_environment(void) {
        const char *e;

        if (get_ctty_devnr(0, NULL) < 0)
                /* Only try to read the command line in daemons.
                   We assume that anything that has a controlling
                   tty is user stuff. */
                (void) parse_proc_cmdline(parse_proc_cmdline_item);

        e = secure_getenv("SYSTEMD_LOG_TARGET");
        if (e && log_set_target_from_string(e) < 0)
                log_warning("Failed to parse log target '%s'. Ignoring.", e);

        e = secure_getenv("SYSTEMD_LOG_LEVEL");
        if (e && log_set_max_level_from_string(e) < 0)
                log_warning("Failed to parse log level '%s'. Ignoring.", e);

        e = secure_getenv("SYSTEMD_LOG_COLOR");
        if (e && log_show_color_from_string(e) < 0)
                log_warning("Failed to parse bool '%s'. Ignoring.", e);

        e = secure_getenv("SYSTEMD_LOG_LOCATION");
        if (e && log_show_location_from_string(e) < 0)
                log_warning("Failed to parse bool '%s'. Ignoring.", e);
}

LogTarget log_get_target(void) {
        return log_target;
}

int log_get_max_level(void) {
        return log_max_level;
}

void log_show_color(bool b) {
        show_color = b;
}

bool log_get_show_color(void) {
        return show_color;
}

void log_show_location(bool b) {
        show_location = b;
}

bool log_get_show_location(void) {
        return show_location;
}

int log_show_color_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_color(t);
        return 0;
}

int log_show_location_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_location(t);
        return 0;
}

bool log_on_console(void) {
        if (log_target == LOG_TARGET_CONSOLE ||
            log_target == LOG_TARGET_CONSOLE_PREFIXED)
                return true;

        return syslog_fd < 0 && kmsg_fd < 0 && journal_fd < 0;
}

static const char *const log_target_table[_LOG_TARGET_MAX] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_CONSOLE_PREFIXED] = "console-prefixed",
        [LOG_TARGET_KMSG] = "kmsg",
        [LOG_TARGET_JOURNAL] = "journal",
        [LOG_TARGET_JOURNAL_OR_KMSG] = "journal-or-kmsg",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_SYSLOG_OR_KMSG] = "syslog-or-kmsg",
        [LOG_TARGET_AUTO] = "auto",
        [LOG_TARGET_SAFE] = "safe",
        [LOG_TARGET_NULL] = "null"
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);

void log_received_signal(int level, const struct signalfd_siginfo *si) {
        if (si->ssi_pid > 0) {
                _cleanup_free_ char *p = NULL;

                get_process_comm(si->ssi_pid, &p);

                log_full(level,
                         "Received SIG%s from PID %"PRIu32" (%s).",
                         signal_to_string(si->ssi_signo),
                         si->ssi_pid, strna(p));
        } else
                log_full(level,
                         "Received SIG%s.",
                         signal_to_string(si->ssi_signo));

}

void log_set_upgrade_syslog_to_journal(bool b) {
        upgrade_syslog_to_journal = b;
}

int log_syntax_internal(
                const char *unit,
                int level,
                const char *config_file,
                unsigned config_line,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) {

        PROTECT_ERRNO;
        char buffer[LINE_MAX];
        int r;
        va_list ap;

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        if (log_target == LOG_TARGET_NULL)
                return -error;

        if (error != 0)
                errno = error;

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        va_end(ap);

        if (unit)
                r = log_struct_internal(
                                level, error,
                                file, line, func,
                                getpid() == 1 ? "UNIT=%s" : "USER_UNIT=%s", unit,
                                LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION),
                                "CONFIG_FILE=%s", config_file,
                                "CONFIG_LINE=%u", config_line,
                                LOG_MESSAGE("[%s:%u] %s", config_file, config_line, buffer),
                                NULL);
        else
                r = log_struct_internal(
                                level, error,
                                file, line, func,
                                LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION),
                                "CONFIG_FILE=%s", config_file,
                                "CONFIG_LINE=%u", config_line,
                                LOG_MESSAGE("[%s:%u] %s", config_file, config_line, buffer),
                                NULL);

        return r;
}
