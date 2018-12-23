/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "compress.h"
#include "fuzz.h"

static int compress(int alg, const void *src, uint64_t src_size, void *dst, size_t dst_alloc_size, size_t *dst_size) {

        if (alg == OBJECT_COMPRESSED_LZ4)
                return compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
        if (alg == OBJECT_COMPRESSED_XZ)
                return compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
        return -EOPNOTSUPP;
}

typedef struct header {
        uint32_t alg : 2; /* We have only two compression algorithms so far, but we might add
                           * more in the future. Let's make this a bit wider so our fuzzer
                           * cases remain stable in the future. */
        uint32_t sw_len;
        uint32_t sw_alloc;
        uint32_t reserved[3]; /* Extra space to keep fuzz cases stable in case we need to
                               * add stuff in the future. */
        uint8_t data[];
} header;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ void *buf = NULL, *buf2 = NULL;
        int r;

        if (size < offsetof(header, data) + 1)
                return 0;

        const header *h = (struct header *) data;
        const size_t data_len = size - offsetof(header, data);

        int alg = h->alg;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        log_info("Using compression %s, data size=%zu", object_compressed_to_string(alg) ?: "(none)", data_len);

        buf = malloc(MAX(size, 128u)); /* Make the buffer a bit larger for very small data */
        if (!buf) {
                log_oom();
                return 0;
        }

        size_t csize;
        r = compress(alg, h->data, data_len, buf, size, &csize);
        if (r < 0) {
                log_error_errno(r, "Compression failed: %m");
                return 0;
        }

        log_debug("Compressed %zu bytes to → %zu bytes", data_len, csize);

        size_t sw_alloc = MAX(h->sw_alloc, 1u);
        buf2 = malloc(sw_alloc);
        if (!buf) {
                log_oom();
                return 0;
        }

        size_t sw_len = MIN(data_len - 1, h->sw_len);

        r = decompress_startswith(alg, buf, csize, &buf2, &sw_alloc, h->data, sw_len, h->data[sw_len]);
        assert_se(r > 0);

        return 0;
}
