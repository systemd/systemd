/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "chattr-util.h"
#include "fd-util.h"
#include "macro.h"

int chattr_fd(int fd, unsigned value, unsigned mask, unsigned *previous) {
        unsigned old_attr, new_attr;
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Explicitly check whether this is a regular file or
         * directory. If it is anything else (such as a device node or
         * fifo), then the ioctl will not hit the file systems but
         * possibly drivers, where the ioctl might have different
         * effects. Notably, DRM is using the same ioctl() number. */

        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                return -ENOTTY;

        if (mask == 0 && !previous)
                return 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &old_attr) < 0)
                return -errno;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr) {
                if (previous)
                        *previous = old_attr;
                return 0;
        }

        if (ioctl(fd, FS_IOC_SETFLAGS, &new_attr) < 0)
                return -errno;

        if (previous)
                *previous = old_attr;

        return 1;
}

int chattr_path(const char *p, unsigned value, unsigned mask, unsigned *previous) {
        _cleanup_close_ int fd = -1;

        assert(p);

        if (mask == 0)
                return 0;

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return chattr_fd(fd, value, mask, previous);
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
