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

#include "util.h"
#include "kdbus.h"

#include "sd-memfd.h"

struct sd_memfd {
        int fd;
        FILE *f;
};

int sd_memfd_new(sd_memfd **m) {
        _cleanup_close_ int kdbus = -1;
        sd_memfd *n;
        int fd;

        if (!m)
                return -EINVAL;

        kdbus = open("/dev/kdbus/control", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (kdbus < 0)
                return -errno;

        if (ioctl(kdbus, KDBUS_CMD_MEMFD_NEW, &fd) < 0)
                return -errno;

        n = new0(struct sd_memfd, 1);
        if (!n)
                return -ENOMEM;

        n->fd = fd;
        *m = n;
        return 0;
}

int sd_memfd_make(int fd, sd_memfd **m) {
        sd_memfd *n;
        uint64_t sz;

        if (!m)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;

        /* Check if this is a valid memfd */
        if (ioctl(fd, KDBUS_CMD_MEMFD_SIZE_GET, &sz) < 0)
                return -ENOTTY;

        n = new0(struct sd_memfd, 1);
        if (!n)
                return -ENOMEM;

        n->fd = fd;
        *m = n;

        return 0;
}

void sd_memfd_free(sd_memfd *m) {
        if (!m)
                return;

        if (m->f)
                fclose(m->f);
        else
                close_nointr_nofail(m->fd);

        free(m);
}

int sd_memfd_get_fd(sd_memfd *m) {
        if (!m)
                return -EINVAL;

        return m->fd;
}

int sd_memfd_get_file(sd_memfd *m, FILE **f) {
        if (!m)
                return -EINVAL;
        if (!f)
                return -EINVAL;

        if (!m->f) {
                m->f = fdopen(m->fd, "r+");
                if (!m->f)
                        return -errno;
        }

        *f = m->f;
        return 0;
}

int sd_memfd_dup_fd(sd_memfd *m) {
        int fd;

        if (!m)
                return -EINVAL;

        fd = fcntl(m->fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0)
                return -errno;

        return fd;
}

int sd_memfd_map(sd_memfd *m, uint64_t offset, size_t size, void **p) {
        void *q;
        int sealed;

        if (!m)
                return -EINVAL;
        if (size <= 0)
                return -EINVAL;
        if (!p)
                return -EINVAL;

        sealed = sd_memfd_get_sealed(m);
        if (sealed < 0)
                return sealed;

        q = mmap(NULL, size, sealed ? PROT_READ : PROT_READ|PROT_WRITE, MAP_SHARED, m->fd, offset);
        if (q == MAP_FAILED)
                return -errno;

        *p = q;
        return 0;
}

int sd_memfd_set_sealed(sd_memfd *m, int b) {
        int r;

        if (!m)
                return -EINVAL;

        r = ioctl(m->fd, KDBUS_CMD_MEMFD_SEAL_SET, b);
        if (r < 0)
                return -errno;

        return 0;
}

int sd_memfd_get_sealed(sd_memfd *m) {
        int r, b;

        if (!m)
                return -EINVAL;

        r = ioctl(m->fd, KDBUS_CMD_MEMFD_SEAL_GET, &b);
        if (r < 0)
                return -errno;

        return !!b;
}

int sd_memfd_get_size(sd_memfd *m, uint64_t *sz) {
        int r;

        if (!m)
                return -EINVAL;
        if (!sz)
                return -EINVAL;

        r = ioctl(m->fd, KDBUS_CMD_MEMFD_SIZE_GET, sz);
        if (r < 0)
                return -errno;

        return r;
}

int sd_memfd_set_size(sd_memfd *m, uint64_t sz) {
        int r;

        if (!m)
                return -EINVAL;

        r = ioctl(m->fd, KDBUS_CMD_MEMFD_SIZE_SET, &sz);
        if (r < 0)
                return -errno;

        return r;
}

int sd_memfd_new_and_map(sd_memfd **m, size_t sz, void **p) {
        sd_memfd *n;
        int r;

        r = sd_memfd_new(&n);
        if (r < 0)
                return r;

        r = sd_memfd_set_size(n, sz);
        if (r < 0) {
                sd_memfd_free(n);
                return r;
        }

        r = sd_memfd_map(n, 0, sz, p);
        if (r < 0) {
                sd_memfd_free(n);
                return r;
        }

        *m = n;
        return 0;
}
