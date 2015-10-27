/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "chattr-util.h"
#include "fd-util.h"
#include "util.h"

int chattr_fd(int fd, unsigned value, unsigned mask) {
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

        if (mask == 0)
                return 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &old_attr) < 0)
                return -errno;

        new_attr = (old_attr & ~mask) | (value & mask);
        if (new_attr == old_attr)
                return 0;

        if (ioctl(fd, FS_IOC_SETFLAGS, &new_attr) < 0)
                return -errno;

        return 1;
}

int chattr_path(const char *p, unsigned value, unsigned mask) {
        _cleanup_close_ int fd = -1;

        assert(p);

        if (mask == 0)
                return 0;

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return chattr_fd(fd, value, mask);
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
