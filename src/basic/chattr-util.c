/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "chattr-util.h"
#include "fd-util.h"
#include "macro.h"

int chattr_full(const char *path, int fd, unsigned value, unsigned mask, unsigned *ret_previous, unsigned *ret_final, bool fallback) {
        _cleanup_close_ int fd_will_close = -1;
        unsigned old_attr, new_attr;
        struct stat st;

        assert(path || fd >= 0);

        if (fd < 0) {
                fd = fd_will_close = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd < 0)
                        return -errno;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Explicitly check whether this is a regular file or directory. If it is anything else (such
         * as a device node or fifo), then the ioctl will not hit the file systems but possibly
         * drivers, where the ioctl might have different effects. Notably, DRM is using the same
         * ioctl() number. */

        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return -ENOTTY;

        if (mask == 0 && !ret_previous && !ret_final)
                return 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &old_attr) < 0)
                return -errno;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr) {
                if (ret_previous)
                        *ret_previous = old_attr;
                if (ret_final)
                        *ret_final = old_attr;
                return 0;
        }

        if (ioctl(fd, FS_IOC_SETFLAGS, &new_attr) >= 0) {
                if (ret_previous)
                        *ret_previous = old_attr;
                if (ret_final)
                        *ret_final = new_attr;
                return 1;
        }

        if (errno != EINVAL || !fallback)
                return -errno;

        /* When -EINVAL is returned, we assume that incompatible attributes are simultaneously
         * specified. E.g., compress(c) and nocow(C) attributes cannot be set to files on btrfs.
         * As a fallback, let's try to set attributes one by one. */

        unsigned current_attr = old_attr;
        for (unsigned i = 0; i < sizeof(unsigned) * 8; i++) {
                unsigned new_one, mask_one = 1u << i;

                if (!FLAGS_SET(mask, mask_one))
                        continue;

                new_one = UPDATE_FLAG(current_attr, mask_one, FLAGS_SET(value, mask_one));
                if (new_one == current_attr)
                        continue;

                if (ioctl(fd, FS_IOC_SETFLAGS, &new_one) < 0) {
                        if (errno != EINVAL)
                                return -errno;
                        continue;
                }

                if (ioctl(fd, FS_IOC_GETFLAGS, &current_attr) < 0)
                        return -errno;
        }

        if (ret_previous)
                *ret_previous = old_attr;
        if (ret_final)
                *ret_final = current_attr;

        return current_attr == new_attr ? 1 : -ENOANO; /* -ENOANO indicates that some attributes cannot be set. */
}

int read_attr_fd(int fd, unsigned *ret) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return -ENOTTY;

        if (ioctl(fd, FS_IOC_GETFLAGS, ret) < 0)
                return -errno;

        return 0;
}

int read_attr_path(const char *p, unsigned *ret) {
        _cleanup_close_ int fd = -1;

        assert(p);
        assert(ret);

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return read_attr_fd(fd, ret);
}
