/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "macro.h"
#include "memfd-util.h"
#include "missing.h"
#include "string-util.h"
#include "utf8.h"

int memfd_new(const char *name) {
        _cleanup_free_ char *g = NULL;
        int fd;

        if (!name) {
                char pr[17] = {};

                /* If no name is specified we generate one. We include
                 * a hint indicating our library implementation, and
                 * add the thread name to it */

                assert_se(prctl(PR_GET_NAME, (unsigned long) pr) >= 0);

                if (isempty(pr))
                        name = "sd";
                else {
                        _cleanup_free_ char *e = NULL;

                        e = utf8_escape_invalid(pr);
                        if (!e)
                                return -ENOMEM;

                        g = strjoin("sd-", e);
                        if (!g)
                                return -ENOMEM;

                        name = g;
                }
        }

        fd = memfd_create(name, MFD_ALLOW_SEALING | MFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

int memfd_map(int fd, uint64_t offset, size_t size, void **p) {
        void *q;
        int sealed;

        assert(fd >= 0);
        assert(size > 0);
        assert(p);

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

        assert(fd >= 0);

        r = fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
        if (r < 0)
                return -errno;

        return 0;
}

int memfd_get_sealed(int fd) {
        int r;

        assert(fd >= 0);

        r = fcntl(fd, F_GET_SEALS);
        if (r < 0)
                return -errno;

        return r == (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
}

int memfd_get_size(int fd, uint64_t *sz) {
        struct stat stat;
        int r;

        assert(fd >= 0);
        assert(sz);

        r = fstat(fd, &stat);
        if (r < 0)
                return -errno;

        *sz = stat.st_size;
        return 0;
}

int memfd_set_size(int fd, uint64_t sz) {
        int r;

        assert(fd >= 0);

        r = ftruncate(fd, sz);
        if (r < 0)
                return -errno;

        return 0;
}

int memfd_new_and_map(const char *name, size_t sz, void **p) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(sz > 0);
        assert(p);

        fd = memfd_new(name);
        if (fd < 0)
                return fd;

        r = memfd_set_size(fd, sz);
        if (r < 0)
                return r;

        r = memfd_map(fd, 0, sz, p);
        if (r < 0)
                return r;

        return TAKE_FD(fd);
}
