/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#if HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif
#include <stdio.h>
#include <sys/prctl.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "macro.h"
#include "memfd-util.h"
#include "missing_fcntl.h"
#include "missing_mman.h"
#include "missing_syscall.h"
#include "string-util.h"
#include "utf8.h"

int memfd_create_wrapper(const char *name, unsigned mode) {
        unsigned mode_compat;
        int mfd;

        mfd = RET_NERRNO(memfd_create(name, mode));
        if (mfd != -EINVAL)
                return mfd;

        mode_compat = mode & ~(MFD_EXEC | MFD_NOEXEC_SEAL);

        if (mode == mode_compat)
                return mfd;

        return RET_NERRNO(memfd_create(name, mode_compat));
}

int memfd_new(const char *name) {
        _cleanup_free_ char *g = NULL;

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

        return memfd_create_wrapper(name, MFD_ALLOW_SEALING | MFD_CLOEXEC | MFD_NOEXEC_SEAL);
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
        assert(fd >= 0);

        return RET_NERRNO(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL));
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

        assert(fd >= 0);
        assert(sz);

        if (fstat(fd, &stat) < 0)
                return -errno;

        *sz = stat.st_size;
        return 0;
}

int memfd_set_size(int fd, uint64_t sz) {
        assert(fd >= 0);

        return RET_NERRNO(ftruncate(fd, sz));
}

int memfd_new_and_map(const char *name, size_t sz, void **p) {
        _cleanup_close_ int fd = -EBADF;
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

int memfd_new_and_seal(const char *name, const void *data, size_t sz) {
        _cleanup_close_ int fd = -EBADF;
        ssize_t n;
        off_t f;
        int r;

        assert(data || sz == 0);

        fd = memfd_new(name);
        if (fd < 0)
                return fd;

        if (sz > 0) {
                n = write(fd, data, sz);
                if (n < 0)
                        return -errno;
                if ((size_t) n != sz)
                        return -EIO;

                f = lseek(fd, 0, SEEK_SET);
                if (f != 0)
                        return -errno;
        }

        r = memfd_set_sealed(fd);
        if (r < 0)
                return r;

        return TAKE_FD(fd);
}
