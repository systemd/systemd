/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "inotify-util.h"
#include "stat-util.h"

bool inotify_event_next(
                union inotify_event_buffer *buffer,
                size_t size,
                struct inotify_event **iterator,
                int log_level) {

        struct inotify_event *e;
        size_t offset = 0;

        assert(buffer);
        assert(iterator);

        if (*iterator) {
                assert((uint8_t*) *iterator >= buffer->raw);
                offset = (uint8_t*) *iterator - buffer->raw;
                offset += offsetof(struct inotify_event, name) + (*iterator)->len;
        }

        if (size == offset)
                return false; /* reached end of list */

        if (size < offset ||
            size - offset < offsetof(struct inotify_event, name)) {
                log_full(log_level, "Received invalid inotify event, ignoring.");
                return false;
        }

        e = CAST_ALIGN_PTR(struct inotify_event, buffer->raw + offset);
        if (size - offset - offsetof(struct inotify_event, name) < e->len) {
                log_full(log_level, "Received invalid inotify event, ignoring.");
                return false;
        }

        *iterator = e;
        return true;
}

int inotify_add_watch_fd(int fd, int what, uint32_t mask) {
        int wd;

        assert(fd >= 0);
        assert(what >= 0);

        /* This is like inotify_add_watch(), except that the file to watch is not referenced by a path, but by an fd */
        wd = inotify_add_watch(fd, FORMAT_PROC_FD_PATH(what), mask);
        if (wd < 0) {
                if (errno != ENOENT)
                        return -errno;

                return proc_fd_enoent_errno();
        }

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
