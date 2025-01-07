/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

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

        assert(name);

        /* Wrapper around memfd_create() which adds compat with older kernels where memfd_create() didn't
         * support MFD_EXEC/MFD_NOEXEC_SEAL. (kernel 6.3+) */

        mfd = RET_NERRNO(memfd_create(name, mode));
        if (mfd != -EINVAL)
                return mfd;

        mode_compat = mode & ~(MFD_EXEC | MFD_NOEXEC_SEAL);

        if (mode == mode_compat)
                return mfd;

        return RET_NERRNO(memfd_create(name, mode_compat));
}

int memfd_new_full(const char *name, unsigned extra_flags) {
        _cleanup_free_ char *g = NULL;

        if (!name) {
                char pr[TASK_COMM_LEN] = {};

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

        return memfd_create_wrapper(
                        name,
                        MFD_CLOEXEC | MFD_NOEXEC_SEAL | extra_flags);
}

int memfd_add_seals(int fd, unsigned seals) {
        assert(fd >= 0);

        return RET_NERRNO(fcntl(fd, F_ADD_SEALS, seals));
}

int memfd_get_seals(int fd, unsigned *ret_seals) {
        int r;

        assert(fd >= 0);

        r = RET_NERRNO(fcntl(fd, F_GET_SEALS));
        if (r < 0)
                return r;

        if (ret_seals)
                *ret_seals = r;
        return 0;
}

int memfd_set_sealed(int fd) {
        return memfd_add_seals(fd, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int memfd_get_sealed(int fd) {
        unsigned int seals;
        int r;

        r = memfd_get_seals(fd, &seals);
        if (r < 0)
                return r;

        /* We ignore F_SEAL_EXEC here to support older kernels. */
        return FLAGS_SET(seals, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int memfd_get_size(int fd, uint64_t *ret) {
        struct stat stat;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &stat) < 0)
                return -errno;

        *ret = stat.st_size;
        return 0;
}

int memfd_set_size(int fd, uint64_t sz) {
        assert(fd >= 0);

        return RET_NERRNO(ftruncate(fd, sz));
}

int memfd_new_and_seal(const char *name, const void *data, size_t sz) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(data || sz == 0);

        if (sz == SIZE_MAX)
                sz = strlen(data);

        fd = memfd_new_full(name, MFD_ALLOW_SEALING);
        if (fd < 0)
                return fd;

        if (sz > 0) {
                ssize_t n = pwrite(fd, data, sz, 0);
                if (n < 0)
                        return -errno;
                if ((size_t) n != sz)
                        return -EIO;
        }

        r = memfd_set_sealed(fd);
        if (r < 0)
                return r;

        return TAKE_FD(fd);
}
