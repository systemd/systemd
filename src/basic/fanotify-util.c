/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>

#include "errno-util.h"
#include "fanotify-util.h"
#include "fd-util.h"
#include "stat-util.h"
#include "unaligned.h"

#define FID_MIN_SIZE (offsetof(struct fanotify_event_info_fid, handle) + offsetof(struct file_handle, f_handle))

bool fanotify_event_iterator_next(FanotifyEventIterator *i, const struct fanotify_event_metadata **ret) {
        assert(i);
        assert(ret);

        if (i->left < sizeof(struct fanotify_event_metadata))
                return false;

        /* Read event_len without going through struct fanotify_event_metadata: the struct requires 64-bit
         * alignment (due to the __aligned_u64 mask field), but 'ptr' may only be 4-byte aligned, as the
         * kernel pads events to FANOTIFY_EVENT_ALIGN (4). */
        uint32_t event_len = unaligned_read_ne32(i->ptr);

        if (event_len < sizeof(struct fanotify_event_metadata) ||
            event_len > i->left ||
            event_len > sizeof(i->aligned.raw))
                return false;

        /* Copy the whole event (metadata + info records) into an 8-byte aligned buffer, so the metadata and
         * the trailing records can be dereferenced safely. */
        memcpy(&i->aligned, i->ptr, event_len);

        i->ptr += event_len;
        i->left -= event_len;

        *ret = &i->aligned.em;
        return true;
}

int fanotify_event_open_by_fid(
                const struct fanotify_event_metadata *e,
                int mount_fd,
                const struct statfs *sfs) {

        assert(e);
        assert(mount_fd >= 0);

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

                return RET_NERRNO(open_by_handle_at(mount_fd, fh, O_CLOEXEC | O_PATH));
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
