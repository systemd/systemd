/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "hexdecoct.h"
#include "sha256.h"
#include "string-util.h"

int sha256_fd(int fd, uint64_t max_size, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        struct sha256_ctx ctx;
        uint64_t total_size = 0;

        sha256_init_ctx(&ctx);

        for (;;) {
                uint8_t buffer[64 * 1024];
                ssize_t n;

                n = read(fd, buffer, sizeof(buffer));
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break;

                if (!INC_SAFE(&total_size, n) || total_size > max_size)
                        return -EFBIG;

                sha256_process_bytes(buffer, n, &ctx);
        }

        sha256_finish_ctx(&ctx, ret);
        return 0;
}

int parse_sha256(const char *s, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        _cleanup_free_ uint8_t *data = NULL;
        size_t size = 0;
        int r;

        if (!sha256_is_valid(s))
                return -EINVAL;

        r = unhexmem_full(s, SHA256_DIGEST_SIZE * 2, false, (void**) &data, &size);
        if (r < 0)
                return r;
        assert(size == SHA256_DIGEST_SIZE);

        memcpy(ret, data, size);
        return 0;
}

bool sha256_is_valid(const char *s) {
        return s && in_charset(s, HEXDIGITS) && (strlen(s) == SHA256_DIGEST_SIZE * 2);
}
