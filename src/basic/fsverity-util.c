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
#include "stat-util.h"
#include "string-util.h"

int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size) {
        struct fsverity_enable_arg params = {
                .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
                .sig_ptr = (uintptr_t) signature,
                .sig_size = signature_size,
                /* Up until kernel 6.3, the fsverity block size must be equal to the page size (and FS block size) */
                .block_size = page_size(),
                .version = 1,
        };
        int r;

        assert(fd >= 0);
        assert(signature || signature_size == 0);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        if (r == -ENOPKG) {
                /* No SHA256 compiled in the kernel? Try with SHA512 before giving up */
                params.hash_algorithm = FS_VERITY_HASH_ALG_SHA512;
                r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        }

        if (r < 0 && !ERRNO_IS_NOT_SUPPORTED(r))
                log_debug_errno(r, "Failed to enable fs-verity on %s: %m", strna(path));
        if (r == 0)
                log_debug("Successfully enabled fs-verity on %s.", strna(path));

        return r;
}

#endif
