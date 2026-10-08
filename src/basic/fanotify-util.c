/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>

#include "fanotify-util.h"
#include "fd-util.h"
#include "stat-util.h"

#define FID_MIN_SIZE (offsetof(struct fanotify_event_info_fid, handle) + offsetof(struct file_handle, f_handle))

int fanotify_event_get_fd(
                const struct fanotify_event_metadata *e,
                int mount_fd,
                const struct statfs *sfs,
                int *ret_fd_close) {

        assert(e);

        if (e->fd >= 0) {
                if (ret_fd_close)
                        *ret_fd_close = -EBADF;
                return e->fd;
        }

        if (mount_fd < 0 || !ret_fd_close)
                return -EINVAL;

        FOREACH_FANOTIFY_EVENT_INFO(h, e) {
                if (h->info_type != FAN_EVENT_INFO_TYPE_FID)
                        continue;

                if (h->len < FID_MIN_SIZE)
                        return -EBADMSG;

                const struct fanotify_event_info_fid *fid = (const struct fanotify_event_info_fid*) h;
                struct file_handle *fh = (struct file_handle*) fid->handle;

                if (h->len < FID_MIN_SIZE + fh->handle_bytes)
                        return -EBADMSG;

                struct statfs our_sfs;
                if (!statfs_is_set(sfs)) {
                        if (fstatfs(mount_fd, &our_sfs) < 0)
                                return -errno;

                        sfs = &our_sfs;
                }

                if (memcmp(&fid->fsid, &sfs->f_fsid, sizeof(fid->fsid)) != 0)
                        return -ESTALE;

                int fd = open_by_handle_at(mount_fd, fh, O_CLOEXEC | O_PATH);
                if (fd < 0)
                        return -errno;

                *ret_fd_close = fd;
                return fd;
        }

        return -ENODATA;
}

int fanotify_mark_fd(int fanotify_fd, unsigned flags, uint64_t mask, int fd) {
        assert(fanotify_fd >= 0);
        assert(fd >= 0);

        /* This also works for O_PATH fds, which fanotify_mark() rejects as dirfd. */

        if (fanotify_mark(fanotify_fd, flags, mask, AT_FDCWD, FORMAT_PROC_FD_PATH(fd)) < 0)
                return -errno;

        return 0;
}
