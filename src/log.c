/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log.h"
#include "util.h"
#include "macro.h"

#define SYSLOG_TIMEOUT_USEC (5*USEC_PER_SEC)
#define LOG_BUFFER_MAX 1024

static LogTarget log_target = LOG_TARGET_CONSOLE;
static int log_max_level = LOG_INFO;

static int console_fd = STDERR_FILENO;
static int syslog_fd = -1;
static int kmsg_fd = -1;

static bool show_color = false;
static bool show_location = false;

/* Akin to glibc's __abort_msg; which is private and we hance cannot
 * use here. */
static char *log_abort_msg = NULL;

void log_close_console(void) {

        if (console_fd < 0)
                return;

        if (getpid() == 1) {
                if (console_fd >= 3)
                        close_nointr_nofail(console_fd);

                console_fd = -1;
        }
}

static int log_open_console(void) {

        if (console_fd >= 0)
                return 0;

        if (getpid() == 1) {

                if ((console_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0) {
                        log_error("Failed to open /dev/console for logging: %s", strerror(-console_fd));
                        return console_fd;
                }

                log_debug("Succesfully opened /dev/console for logging.");
        } else
                console_fd = STDERR_FILENO;

        return 0;
}

void log_close_kmsg(void) {

        if (kmsg_fd < 0)
                return;

        close_nointr_nofail(kmsg_fd);
        kmsg_fd = -1;
}

static int log_open_kmsg(void) {

        if (kmsg_fd >= 0)
                return 0;

        if ((kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0) {
                log_info("Failed to open /dev/kmsg for logging: %s", strerror(errno));
                return -errno;
        }

        log_debug("Succesfully opened /dev/kmsg for logging.");

        return 0;
}

void log_close_syslog(void) {

        if (syslog_fd < 0)
                return;

        close_nointr_nofail(syslog_fd);
        syslog_fd = -1;
}

static int log_open_syslog(void) {
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;
        struct timeval tv;
        int r;

        if (syslog_fd >= 0)
                return 0;

        if ((syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
                r = -errno;
                goto fail;
        }

        /* Make sure we don't block for more than 5s when talking to
         * syslog */
        timeval_store(&tv, SYSLOG_TIMEOUT_USEC);
        if (setsockopt(syslog_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                r = -errno;
                goto fail;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/dev/log", sizeof(sa.un.sun_path));

        if (connect(syslog_fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                goto fail;
        }

        log_debug("Succesfully opened syslog for logging.");

        return 0;

fail:
        log_close_syslog();
        log_info("Failed to open syslog for logging: %s", strerror(-r));
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
                log_close_syslog();
                log_close_console();
                return 0;
        }

        if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
            log_target == LOG_TARGET_SYSLOG)
                if ((r = log_open_syslog()) >= 0) {
                        log_close_console();
                        return r;
                }

        if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
            log_target == LOG_TARGET_KMSG)
                if ((r = log_open_kmsg()) >= 0) {
                        log_close_syslog();
                        log_close_console();
                        return r;
                }

        log_close_syslog();
        return log_open_console();
}

void log_set_target(LogTarget target) {
        assert(target >= 0);
        assert(target < _LOG_TARGET_MAX);

        log_target = target;
}

void log_set_max_level(int level) {
        assert((level & LOG_PRIMASK) == level);

        log_max_level = level;
}

static int write_to_console(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *buffer) {

        char location[64];
        struct iovec iovec[5];
        unsigned n = 0;
        bool highlight;

        if (console_fd < 0)
                return 0;

        snprintf(location, sizeof(location), "(%s:%u) ", file, line);
        char_array_0(location);

        highlight = LOG_PRI(level) <= LOG_ERR && show_color;

        zero(iovec);
        if (show_location)
                IOVEC_SET_STRING(iovec[n++], location);
        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_ON);
        IOVEC_SET_STRING(iovec[n++], buffer);
        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_OFF);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(console_fd, iovec, n) < 0)
                return -errno;

        return 1;
}

static int write_to_syslog(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *buffer) {

        char header_priority[16], header_time[64], header_pid[16];
        struct iovec iovec[5];
        struct msghdr msghdr;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control;
        struct ucred *ucred;
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(level)));
        char_array_0(header_priority);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        if (!(tm = localtime(&t)))
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) getpid());
        char_array_0(header_pid);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        zero(control);
        control.cmsghdr.cmsg_level = SOL_SOCKET;
        control.cmsghdr.cmsg_type = SCM_CREDENTIALS;
        control.cmsghdr.cmsg_len = CMSG_LEN(sizeof(struct ucred));

        ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
        ucred->pid = getpid();
        ucred->uid = getuid();
        ucred->gid = getgid();

        zero(msghdr);
        msghdr.msg_iov = iovec;
        msghdr.msg_iovlen = ELEMENTSOF(iovec);
        msghdr.msg_control = &control;
        msghdr.msg_controllen = control.cmsghdr.cmsg_len;

        if (sendmsg(syslog_fd, &msghdr, MSG_NOSIGNAL) < 0)
                return -errno;

        return 1;
}

static int write_to_kmsg(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *buffer) {

        char header_priority[16], header_pid[16];
        struct iovec iovec[5];

        if (kmsg_fd < 0)
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", LOG_PRI(level));
        char_array_0(header_priority);

        snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) getpid());
        char_array_0(header_pid);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], "\n");

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 1;
}

static int log_dispatch(
        int level,
        const char*file,
        int line,
        const char *func,
        char *buffer) {

        int r = 0;

        if (log_target == LOG_TARGET_NULL)
                return 0;

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {

                        if ((k = write_to_syslog(level, file, line, func, buffer)) < 0) {
                                log_close_syslog();
                                log_open_kmsg();
                        } else if (k > 0)
                                r++;
                }

                if (k <= 0 &&
                    (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                     log_target == LOG_TARGET_KMSG)) {

                        if ((k = write_to_kmsg(level, file, line, func, buffer)) < 0) {
                                log_close_kmsg();
                                log_open_console();
                        } else if (k > 0)
                                r++;
                }

                if (k <= 0 &&
                    (k = write_to_console(level, file, line, func, buffer)) < 0)
                        return k;

                buffer = e;
        } while (buffer);

        return r;
}

int log_dump_internal(
        int level,
        const char*file,
        int line,
        const char *func,
        char *buffer) {

        int saved_errno, r;

        /* This modifies the buffer... */

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        saved_errno = errno;
        r = log_dispatch(level, file, line, func, buffer);
        errno = saved_errno;

        return r;
}

int log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        char buffer[LOG_BUFFER_MAX];
        int saved_errno, r;
        va_list ap;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        saved_errno = errno;

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        va_end(ap);

        char_array_0(buffer);

        r = log_dispatch(level, file, line, func, buffer);
        errno = saved_errno;

        return r;
}

void log_assert(
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        static char buffer[LOG_BUFFER_MAX];
        int saved_errno = errno;
        va_list ap;

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        va_end(ap);

        char_array_0(buffer);
        log_abort_msg = buffer;

        log_dispatch(LOG_CRIT, file, line, func, buffer);
        abort();

        /* If the user chose to ignore this SIGABRT, we are happy to go on, as if nothing happened. */
        errno = saved_errno;
}

int log_set_target_from_string(const char *e) {
        LogTarget t;

        if ((t = log_target_from_string(e)) < 0)
                return -EINVAL;

        log_set_target(t);
        return 0;
}

int log_set_max_level_from_string(const char *e) {
        int t;

        if ((t = log_level_from_string(e)) < 0)
                return -EINVAL;

        log_set_max_level(t);
        return 0;
}

void log_parse_environment(void) {
        const char *e;

        if ((e = getenv("SYSTEMD_LOG_TARGET")))
                if (log_set_target_from_string(e) < 0)
                        log_warning("Failed to parse log target %s. Ignoring.", e);

        if ((e = getenv("SYSTEMD_LOG_LEVEL")))
                if (log_set_max_level_from_string(e) < 0)
                        log_warning("Failed to parse log level %s. Ignoring.", e);

        if ((e = getenv("SYSTEMD_LOG_COLOR")))
                if (log_show_color_from_string(e) < 0)
                        log_warning("Failed to parse bool %s. Ignoring.", e);

        if ((e = getenv("SYSTEMD_LOG_LOCATION"))) {
                if (log_show_location_from_string(e) < 0)
                        log_warning("Failed to parse bool %s. Ignoring.", e);
        }
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

void log_show_location(bool b) {
        show_location = b;
}

int log_show_color_from_string(const char *e) {
        int t;

        if ((t = parse_boolean(e)) < 0)
                return -EINVAL;

        log_show_color(t);
        return 0;
}

int log_show_location_from_string(const char *e) {
        int t;

        if ((t = parse_boolean(e)) < 0)
                return -EINVAL;

        log_show_location(t);
        return 0;
}

static const char *const log_target_table[] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_KMSG] = "kmsg",
        [LOG_TARGET_SYSLOG_OR_KMSG] = "syslog-or-kmsg",
        [LOG_TARGET_NULL] = "null"
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);
