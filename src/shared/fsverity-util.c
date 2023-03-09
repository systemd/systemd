/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LINUX_FSVERITY_H

#include <linux/fsverity.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fsverity-util.h"
#include "string-util.h"

int fsverity_enable(const char *path, const void *signature, size_t signature_size) {
        struct fsverity_enable_arg params = {
                .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
                .sig_ptr = (uintptr_t) signature,
                .sig_size = signature_size,
                .block_size = 4096, /* Common enough default in case we can't get it from sysconf() */
                .version = 1,
        };
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);
        assert(signature || signature_size == 0);

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        /* Up until kernel 6.3, the fsverity block size must be equal to the page size (and FS block size) */
        r = sysconf(_SC_PAGESIZE);
        if (r > 0)
                params.block_size = r;

        r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        if (r == -ENOPKG) {
                /* No SHA256 compiled in the kernel? Try with SHA512 before giving up */
                params.hash_algorithm = FS_VERITY_HASH_ALG_SHA512;
                r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        }

        return r;
}

#endif
