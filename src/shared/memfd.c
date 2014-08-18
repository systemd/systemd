/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "util.h"
#include "bus-label.h"
#include "missing.h"
#include "memfd.h"

#include "sd-bus.h"

int memfd_new(int *fd, const char *name) {

        _cleanup_free_ char *g = NULL;
        int n;

        assert_return(fd, -EINVAL);

        if (name) {
                /* The kernel side is pretty picky about the character
                 * set here, let's do the usual bus escaping to deal
                 * with that. */

                g = bus_label_escape(name);
                if (!g)
                        return -ENOMEM;

                name = g;

        } else {
                char pr[17] = {};

                /* If no name is specified we generate one. We include
                 * a hint indicating our library implementation, and
                 * add the thread name to it */

                assert_se(prctl(PR_GET_NAME, (unsigned long) pr) >= 0);

                if (isempty(pr))
                        name = "sd";
                else {
                        _cleanup_free_ char *e = NULL;

                        e = bus_label_escape(pr);
                        if (!e)
                                return -ENOMEM;

                        g = strappend("sd-", e);
                        if (!g)
                                return -ENOMEM;

                        name = g;
                }
        }

        n = memfd_create(name, MFD_ALLOW_SEALING);
        if (n < 0)
                return -errno;

        *fd = n;
        return 0;
}

int memfd_map(int fd, uint64_t offset, size_t size, void **p) {
        void *q;
        int sealed;

        assert_return(fd >= 0, -EINVAL);
        assert_return(size > 0, -EINVAL);
        assert_return(p, -EINVAL);

        sealed = memfd_get_sealed(fd);
        if (sealed < 0)
                return sealed;

        if (sealed)
                q = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
        else
                q = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);

        if (q == MAP_FAILED)
                return -errno;

        *p = q;
        return 0;
}

int memfd_set_sealed(int fd) {
        int r;

        assert_return(fd >= 0, -EINVAL);

        r = fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
        if (r < 0)
                return -errno;

        return 0;
}

int memfd_get_sealed(int fd) {
        int r;

        assert_return(fd >= 0, -EINVAL);

        r = fcntl(fd, F_GET_SEALS);
        if (r < 0)
                return -errno;

        return (r & (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)) ==
                    (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int memfd_get_size(int fd, uint64_t *sz) {
        int r;
        struct stat stat;

        assert_return(fd >= 0, -EINVAL);
        assert_return(sz, -EINVAL);

        r = fstat(fd, &stat);
        if (r < 0)
                return -errno;

        *sz = stat.st_size;
        return r;
}

int memfd_set_size(int fd, uint64_t sz) {
        int r;

        assert_return(fd >= 0, -EINVAL);

        r = ftruncate(fd, sz);
        if (r < 0)
                return -errno;

        return r;
}

int memfd_new_and_map(int *fd, const char *name, size_t sz, void **p) {
        _cleanup_close_ int n = -1;
        int r;

        r = memfd_new(&n, name);
        if (r < 0)
                return r;

        r = memfd_set_size(n, sz);
        if (r < 0)
                return r;

        r = memfd_map(n, 0, sz, p);
        if (r < 0)
                return r;

        *fd = n;
        n = -1;
        return 0;
}

int memfd_get_name(int fd, char **name) {
        char path[sizeof("/proc/self/fd/") + DECIMAL_STR_MAX(int)], buf[FILENAME_MAX+1], *e;
        const char *delim, *end;
        _cleanup_free_ char *n = NULL;
        ssize_t k;

        assert_return(fd >= 0, -EINVAL);
        assert_return(name, -EINVAL);

        sprintf(path, "/proc/self/fd/%i", fd);

        k = readlink(path, buf, sizeof(buf));
        if (k < 0)
                return -errno;

        if ((size_t) k >= sizeof(buf))
                return -E2BIG;

        buf[k] = 0;

        delim = strstr(buf, ":[");
        if (!delim)
                return -EIO;

        delim = strchr(delim + 2, ':');
        if (!delim)
                return -EIO;

        delim++;

        end = strchr(delim, ']');
        if (!end)
                return -EIO;

        n = strndup(delim, end - delim);
        if (!n)
                return -ENOMEM;

        e = bus_label_unescape(n);
        if (!e)
                return -ENOMEM;

        *name = e;

        return 0;
}
