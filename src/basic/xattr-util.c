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

#include <sys/xattr.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "sparse-endian.h"
#include "stdio-util.h"
#include "util.h"
#include "xattr-util.h"

int getxattr_malloc(const char *path, const char *name, char **value, bool allow_symlink) {
        char *v;
        size_t l;
        ssize_t n;

        assert(path);
        assert(name);
        assert(value);

        for (l = 100; ; l = (size_t) n + 1) {
                v = new0(char, l);
                if (!v)
                        return -ENOMEM;

                if (allow_symlink)
                        n = lgetxattr(path, name, v, l);
                else
                        n = getxattr(path, name, v, l);

                if (n >= 0 && (size_t) n < l) {
                        *value = v;
                        return n;
                }

                free(v);

                if (n < 0 && errno != ERANGE)
                        return -errno;

                if (allow_symlink)
                        n = lgetxattr(path, name, NULL, 0);
                else
                        n = getxattr(path, name, NULL, 0);
                if (n < 0)
                        return -errno;
        }
}

int fgetxattr_malloc(int fd, const char *name, char **value) {
        char *v;
        size_t l;
        ssize_t n;

        assert(fd >= 0);
        assert(name);
        assert(value);

        for (l = 100; ; l = (size_t) n + 1) {
                v = new0(char, l);
                if (!v)
                        return -ENOMEM;

                n = fgetxattr(fd, name, v, l);

                if (n >= 0 && (size_t) n < l) {
                        *value = v;
                        return n;
                }

                free(v);

                if (n < 0 && errno != ERANGE)
                        return -errno;

                n = fgetxattr(fd, name, NULL, 0);
                if (n < 0)
                        return -errno;
        }
}

ssize_t fgetxattrat_fake(int dirfd, const char *filename, const char *attribute, void *value, size_t size, int flags) {
        char fn[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_close_ int fd = -1;
        ssize_t l;

        /* The kernel doesn't have a fgetxattrat() command, hence let's emulate one */

        fd = openat(dirfd, filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH|(flags & AT_SYMLINK_NOFOLLOW ? O_NOFOLLOW : 0));
        if (fd < 0)
                return -errno;

        xsprintf(fn, "/proc/self/fd/%i", fd);

        l = getxattr(fn, attribute, value, size);
        if (l < 0)
                return -errno;

        return l;
}

static int parse_crtime(le64_t le, usec_t *usec) {
        uint64_t u;

        assert(usec);

        u = le64toh(le);
        if (u == 0 || u == (uint64_t) -1)
                return -EIO;

        *usec = (usec_t) u;
        return 0;
}

int fd_getcrtime(int fd, usec_t *usec) {
        le64_t le;
        ssize_t n;

        assert(fd >= 0);
        assert(usec);

        /* Until Linux gets a real concept of birthtime/creation time,
         * let's fake one with xattrs */

        n = fgetxattr(fd, "user.crtime_usec", &le, sizeof(le));
        if (n < 0)
                return -errno;
        if (n != sizeof(le))
                return -EIO;

        return parse_crtime(le, usec);
}

int fd_getcrtime_at(int dirfd, const char *name, usec_t *usec, int flags) {
        le64_t le;
        ssize_t n;

        n = fgetxattrat_fake(dirfd, name, "user.crtime_usec", &le, sizeof(le), flags);
        if (n < 0)
                return -errno;
        if (n != sizeof(le))
                return -EIO;

        return parse_crtime(le, usec);
}

int path_getcrtime(const char *p, usec_t *usec) {
        le64_t le;
        ssize_t n;

        assert(p);
        assert(usec);

        n = getxattr(p, "user.crtime_usec", &le, sizeof(le));
        if (n < 0)
                return -errno;
        if (n != sizeof(le))
                return -EIO;

        return parse_crtime(le, usec);
}

int fd_setcrtime(int fd, usec_t usec) {
        le64_t le;

        assert(fd >= 0);

        if (usec <= 0)
                usec = now(CLOCK_REALTIME);

        le = htole64((uint64_t) usec);
        if (fsetxattr(fd, "user.crtime_usec", &le, sizeof(le), 0) < 0)
                return -errno;

        return 0;
}
