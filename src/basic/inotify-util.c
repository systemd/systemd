/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "inotify-util.h"

int inotify_add_watch_fd(int fd, int what, uint32_t mask) {
        int wd;

        /* This is like inotify_add_watch(), except that the file to watch is not referenced by a path, but by an fd */
        wd = inotify_add_watch(fd, FORMAT_PROC_FD_PATH(what), mask);
        if (wd < 0)
                return -errno;

        return wd;
}

int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask) {
        int wd;

        wd = inotify_add_watch(fd, pathname, mask);
        if (wd < 0) {
                if (errno == ENOSPC)
                        return log_error_errno(errno, "Failed to add a watch for %s: inotify watch limit reached", pathname);

                return log_error_errno(errno, "Failed to add a watch for %s: %m", pathname);
        }

        return wd;
}
