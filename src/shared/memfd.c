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

struct sd_memfd {
        int fd;
        FILE *f;
};

int sd_memfd_new(sd_memfd **m, const char *name) {

        _cleanup_free_ char *g = NULL;
        sd_memfd *n;

        assert_return(m, -EINVAL);

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

        n = new0(struct sd_memfd, 1);
        if (!n)
                return -ENOMEM;

        n->fd = memfd_create(name, MFD_ALLOW_SEALING);
        if (n->fd < 0) {
                free(n);
                return -errno;
        }

        *m = n;
        return 0;
}

int sd_memfd_new_from_fd(sd_memfd **m, int fd) {
        sd_memfd *n;

        assert_return(m, -EINVAL);
        assert_return(fd >= 0, -EINVAL);

        /* Check if this is a sealable fd */
        if (fcntl(fd, F_GET_SEALS) < 0)
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
                safe_close(m->fd);

        free(m);
}

int sd_memfd_get_fd(sd_memfd *m) {
        assert_return(m, -EINVAL);

        return m->fd;
}

int sd_memfd_get_file(sd_memfd *m, FILE **f) {
        assert_return(m, -EINVAL);
        assert_return(f, -EINVAL);

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

        assert_return(m, -EINVAL);

        fd = fcntl(m->fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0)
                return -errno;

        return fd;
}

int sd_memfd_map(sd_memfd *m, uint64_t offset, size_t size, void **p) {
        void *q;
        int sealed;

        assert_return(m, -EINVAL);
        assert_return(size > 0, -EINVAL);
        assert_return(p, -EINVAL);

        sealed = sd_memfd_get_sealed(m);
        if (sealed < 0)
                return sealed;

        q = mmap(NULL, size, sealed ? PROT_READ : PROT_READ|PROT_WRITE, MAP_PRIVATE, m->fd, offset);
        if (q == MAP_FAILED)
                return -errno;

        *p = q;
        return 0;
}

int sd_memfd_set_sealed(sd_memfd *m) {
        int r;

        assert_return(m, -EINVAL);

        r = fcntl(m->fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
        if (r < 0)
                return -errno;

        return 0;
}

int sd_memfd_get_sealed(sd_memfd *m) {
        int r;

        assert_return(m, -EINVAL);

        r = fcntl(m->fd, F_GET_SEALS);
        if (r < 0)
                return -errno;

        return (r & (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)) ==
                    (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int sd_memfd_get_size(sd_memfd *m, uint64_t *sz) {
        int r;
        struct stat stat;

        assert_return(m, -EINVAL);
        assert_return(sz, -EINVAL);

        r = fstat(m->fd, &stat);
        if (r < 0)
                return -errno;

        *sz = stat.st_size;
        return r;
}

int sd_memfd_set_size(sd_memfd *m, uint64_t sz) {
        int r;

        assert_return(m, -EINVAL);

        r = ftruncate(m->fd, sz);
        if (r < 0)
                return -errno;

        return r;
}

int sd_memfd_new_and_map(sd_memfd **m, const char *name, size_t sz, void **p) {
        sd_memfd *n;
        int r;

        r = sd_memfd_new(&n, name);
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

int sd_memfd_get_name(sd_memfd *m, char **name) {
        char path[sizeof("/proc/self/fd/") + DECIMAL_STR_MAX(int)], buf[FILENAME_MAX+1], *e;
        const char *delim, *end;
        _cleanup_free_ char *n = NULL;
        ssize_t k;

        assert_return(m, -EINVAL);
        assert_return(name, -EINVAL);

        sprintf(path, "/proc/self/fd/%i", m->fd);

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
