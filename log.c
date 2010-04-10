/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
static int log_max_level = LOG_DEBUG;

static int syslog_fd = -1;
static int kmsg_fd = -1;

void log_close_kmsg(void) {

        if (kmsg_fd >= 0) {
                close_nointr(kmsg_fd);
                kmsg_fd = -1;
        }
}

int log_open_kmsg(void) {

        if (log_target != LOG_TARGET_KMSG) {
                log_close_kmsg();
                return 0;
        }

        if (kmsg_fd >= 0)
                return 0;

        if ((kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0) {
                log_info("Failed to open syslog for logging: %s", strerror(errno));
                return -errno;
        }

        log_info("Succesfully opened /dev/kmsg for logging.");

        return 0;
}

void log_close_syslog(void) {

        if (syslog_fd >= 0) {
                close_nointr(syslog_fd);
                syslog_fd = -1;
        }
}

int log_open_syslog(void) {
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;
        struct timeval tv;
        int r;

        if (log_target != LOG_TARGET_SYSLOG) {
                log_close_syslog();
                return 0;
        }

        if (syslog_fd >= 0)
                return 0;

        if ((syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0)
                return -errno;

        /* Make sure we don't block for more than 5s when talking to
         * syslog */
        timeval_store(&tv, SYSLOG_TIMEOUT_USEC);
        if (setsockopt(syslog_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                r = -errno;
                log_close_syslog();
                return r;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/dev/log", sizeof(sa.un.sun_path));

        if (connect(syslog_fd, &sa.sa, sizeof(sa)) < 0) {
                r = -errno;
                log_close_syslog();

                log_info("Failed to open syslog for logging: %s", strerror(-r));
                return r;
        }

        log_info("Succesfully opened syslog for logging.");

        return 0;
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

static void write_to_console(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap) {

        const char *prefix, *suffix;

        if (LOG_PRI(level) <= LOG_ERR) {
                prefix = "\x1B[1;31m";
                suffix = "\x1B[0m";
        } else {
                prefix = "";
                suffix = "";
        }

        fprintf(stderr, "(%s:%u) %s", file, line, prefix);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "%s\n", suffix);
}

static int write_to_syslog(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap) {

        char header_priority[16], header_time[64], header_pid[16];
        char buffer[LOG_BUFFER_MAX];
        struct iovec iovec[5];
        struct msghdr msghdr;
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return -EIO;

        snprintf(header_priority, sizeof(header_priority), "<%i>", LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(level)));
        char_array_0(header_priority);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        if (!(tm = localtime(&t)))
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        snprintf(header_pid, sizeof(header_pid), "[%llu]: ", (unsigned long long) getpid());
        char_array_0(header_pid);

        vsnprintf(buffer, sizeof(buffer), format, ap);
        char_array_0(buffer);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], __progname);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        zero(msghdr);
        msghdr.msg_iov = iovec;
        msghdr.msg_iovlen = ELEMENTSOF(iovec);

        if (sendmsg(syslog_fd, &msghdr, 0) < 0)
                return -errno;

        return 0;
}

static int write_to_kmsg(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap) {

        char header_priority[16], header_pid[16];
        char buffer[LOG_BUFFER_MAX];
        struct iovec iovec[5];

        if (kmsg_fd < 0)
                return -EIO;

        snprintf(header_priority, sizeof(header_priority), "<%i>", LOG_PRI(level));
        char_array_0(header_priority);

        snprintf(header_pid, sizeof(header_pid), "[%llu]: ", (unsigned long long) getpid());
        char_array_0(header_pid);

        vsnprintf(buffer, sizeof(buffer), format, ap);
        char_array_0(buffer);

        zero(iovec);
        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], __progname);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], (char*) "\n");

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 0;
}

void log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        va_list ap;
        bool written;
        int saved_errno;

        if (LOG_PRI(level) > log_max_level)
                return;

        saved_errno = errno;
        written = false;

        if (log_target == LOG_TARGET_KMSG) {
                va_start(ap, format);
                written = write_to_kmsg(level, file, line, func, format, ap) >= 0;
                va_end(ap);
        } else if (log_target == LOG_TARGET_SYSLOG) {
                va_start(ap, format);
                written = write_to_syslog(level, file, line, func, format, ap) >= 0;
                va_end(ap);
        }

        if (!written) {
                va_start(ap, format);
                write_to_console(level, file, line, func, format, ap);
                va_end(ap);
        }

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
}

LogTarget log_get_target(void) {
        return log_target;
}

int log_get_max_level(void) {
        return log_max_level;
}

static const char *const log_target_table[] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_KMSG] = "kmsg",
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);
