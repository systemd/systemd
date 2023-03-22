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
#include "sha256.h"
#include "hexdecoct.h"

int fsverity_enable(int fd, const char *path, const void *signature, size_t signature_size) {
        struct fsverity_enable_arg params = {
                .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
                .sig_ptr = (uintptr_t) signature,
                .sig_size = signature_size,
                /* Up until kernel 6.3, the fsverity block size must be equal to the page size (and FS block size) */
                .block_size = page_size(),
                .version = 1,
        };
        _cleanup_close_ int read_only_fd = -EBADF;
        int r;

        assert(fd >= 0 || path);
        assert(path);
        assert(signature || signature_size == 0);

        if (fd == -EBADF) {
                fd = read_only_fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return -errno;
        }

        r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        if (r == -ENOPKG) {
                /* No SHA256 compiled in the kernel? Try with SHA512 before giving up */
                params.hash_algorithm = FS_VERITY_HASH_ALG_SHA512;
                r = RET_NERRNO(ioctl(fd, FS_IOC_ENABLE_VERITY, &params));
        }

        if (r == 0)
                log_debug("Successfully enabled fs-verity on %s.", path);

        if (signature) {
                uint8_t buffer[SHA256_DIGEST_SIZE];
                sha256_direct(signature, signature_size, buffer);
                log_info("DBG: fs-verity signature for %s: %s", path, hexmem(buffer, sizeof(buffer)));
        }

        return r;
}

#endif
