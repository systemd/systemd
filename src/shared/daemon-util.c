/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "alloc-util.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "time-util.h"

static int notify_remove_fd_full(int log_level, const char *name) {
        int r;

        assert(name);

        r = sd_notifyf(/* unset_environment = */ false,
                       "FDSTOREREMOVE=1\n"
                       "FDNAME=%s", name);
        if (r < 0)
                return log_full_errno(
                                log_level, r,
                                "Failed to remove file descriptor \"%s\" from the store, ignoring: %m",
                                name);

        return 0;
}

int notify_remove_fd(const char *name) {
        return notify_remove_fd_full(LOG_DEBUG, name);
}

int notify_remove_fd_warn(const char *name) {
        return notify_remove_fd_full(LOG_WARNING, name);
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

        return sd_pid_notify_with_fds(0, /* unset_environment = */ false, state, &fd, 1);
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

int notify_reloading_full(const char *status) {
        int r;

        r = sd_notifyf(/* unset_environment = */ false,
                       "RELOADING=1\n"
                       "MONOTONIC_USEC=" USEC_FMT
                       "%s%s",
                       now(CLOCK_MONOTONIC),
                       status ? "\nSTATUS=" : "", strempty(status));
        if (r < 0)
                return log_debug_errno(r, "Failed to notify service manager for reloading status: %m");

        return 0;
}
