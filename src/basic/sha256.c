/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "hexdecoct.h"
#include "sha256.h"

int sha256_fd(int fd, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        struct sha256_ctx ctx;

        sha256_init_ctx(&ctx);

        for (;;) {
                uint8_t buffer[64 * 1024];
                ssize_t n;

                n = read(fd, buffer, sizeof(buffer));
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break;

                sha256_process_bytes(buffer, n, &ctx);
        }

        sha256_finish_ctx(&ctx, ret);
        return 0;
}

int parse_sha256(const char *s, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        _cleanup_free_ uint8_t *data = NULL;
        size_t size = 0;
        int r;

        if (!valid_sha256(s))
                return -EINVAL;

        r = unhexmem_full(s, SHA256_DIGEST_SIZE * 2, false, (void**) &data, &size);
        if (r < 0)
                return r;
        if (size != SHA256_DIGEST_SIZE)
                return -EINVAL;

        memcpy(ret, data, size);
        return 0;
}
