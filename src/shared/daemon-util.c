/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "alloc-util.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "iovec-util.h"
#include "log.h"
#include "parse-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

int notify_remove_fd_warn(const char *name) {
        int r;

        assert(name);

        r = sd_notifyf(/* unset_environment= */ false,
                       "FDSTOREREMOVE=1\n"
                       "FDNAME=%s", name);
        if (r < 0)
                return log_full_errno(
                                ERRNO_IS_NEG_DISCONNECT(r) ? LOG_DEBUG : LOG_WARNING, r,
                                "Failed to remove file descriptor \"%s\" from the store, ignoring: %m",
                                name);

        return 0;
}

int notify_remove_fd_warnf(const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);
        if (r < 0)
                return log_oom();

        return notify_remove_fd_warn(p);
}

int close_and_notify_warn(int fd, const char *name) {
        if (name)
                (void) notify_remove_fd_warn(name);

        return safe_close(fd);
}

int notify_push_fd(int fd, const char *name) {
        _cleanup_free_ char *state = NULL;

        assert(fd >= 0);
        assert(name);

        state = strjoin("FDSTORE=1\n"
                        "FDNAME=", name);
        if (!state)
                return -ENOMEM;

        /* Remove existing fds with the same name in fdstore. */
        (void) notify_remove_fd_warn(name);

        return sd_pid_notify_with_fds(0, /* unset_environment= */ false, state, &fd, 1);
}

int notify_push_fdf(int fd, const char *format, ...) {
        _cleanup_free_ char *name = NULL;
        va_list ap;
        int r;

        assert(fd >= 0);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&name, format, ap);
        va_end(ap);
        if (r < 0)
                return -ENOMEM;

        return notify_push_fd(fd, name);
}

bool fdstore_detected(void) {
        static int cached = -1;
        int r;

        if (cached >= 0)
                return cached;

        const char *e = getenv("FDSTORE");
        if (isempty(e))
                return (cached = 0);

        unsigned u;
        r = safe_atou(e, &u);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse 'FDSTORE=%s', ignoring: %m", e);
                return (cached = 0);
        }

        return (cached = u > 0);
}

int notify_reloading_full(const char *status) {
        int r;

        r = sd_notifyf(/* unset_environment= */ false,
                       "RELOADING=1\n"
                       "MONOTONIC_USEC=" USEC_FMT
                       "%s%s",
                       now(CLOCK_MONOTONIC),
                       status ? "\nSTATUS=" : "", strempty(status));
        if (r < 0)
                return log_debug_errno(r, "Failed to notify service manager for reloading status: %m");

        return 0;
}

int notify_send_coredump(const char *socket_path, int pidfd, int signo) {
        char message[STRLEN(NOTIFY_COREDUMP_MESSAGE "\n" NOTIFY_COREDUMP_SIGNAL_PREFIX) + DECIMAL_STR_MAX(int)];
        union sockaddr_union sa = {};
        ssize_t n;
        int r;

        assert(socket_path);
        assert(pidfd >= 0);
        assert(SIGNAL_VALID(signo));

        r = sockaddr_un_set_path(&sa.un, socket_path);
        if (r < 0)
                return r;
        socklen_t sa_len = r;

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        xsprintf(message, NOTIFY_COREDUMP_MESSAGE "\n" NOTIFY_COREDUMP_SIGNAL_PREFIX "%i", signo);

        struct iovec iovec = IOVEC_MAKE_STRING(message);
        n = send_one_fd_iov_sa(fd, pidfd, &iovec, 1, &sa.sa, sa_len, MSG_DONTWAIT);
        if (n < 0)
                return (int) n;
        if ((size_t) n != iovec.iov_len)
                return -EIO;

        return 1;
}
