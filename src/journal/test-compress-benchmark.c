/***
  This file is part of systemd

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "compress.h"
#include "util.h"
#include "macro.h"

typedef int (compress_t)(const void *src, uint64_t src_size, void *dst, size_t *dst_size);
typedef int (decompress_t)(const void *src, uint64_t src_size,
                           void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);

#define MAX_SIZE (1024*1024LU)

static char* make_buf(size_t count) {
        char *buf;
        size_t i;

        buf = malloc(count);
        assert_se(buf);

        for (i = 0; i < count; i++)
                buf[i] = 'a' + i % ('z' - 'a' + 1);

        return buf;
}

static void test_compress_decompress(const char* label,
                                     compress_t compress, decompress_t decompress) {
        usec_t n, n2 = 0;
        float dt;

        _cleanup_free_ char *text, *buf;
        _cleanup_free_ void *buf2 = NULL;
        size_t buf2_allocated = 0;
        size_t skipped = 0, compressed = 0, total = 0;

        text = make_buf(MAX_SIZE);
        buf = calloc(MAX_SIZE + 1, 1);
        assert_se(text && buf);

        n = now(CLOCK_MONOTONIC);

        for (size_t i = 1; i <= MAX_SIZE; i += (i < 2048 ? 1 : 217)) {
                size_t j = 0, k = 0;
                int r;

                r = compress(text, i, buf, &j);
                /* assume compression must be successful except for small inputs */
                assert_se(r == 0 || (i < 2048 && r == -ENOBUFS));
                /* check for overwrites */
                assert_se(buf[i] == 0);
                if (r != 0) {
                        skipped += i;
                        continue;
                }

                assert_se(j > 0);
                if (j >= i)
                        log_error("%s \"compressed\" %zu -> %zu", label, i, j);

                r = decompress(buf, j, &buf2, &buf2_allocated, &k, 0);
                assert_se(r == 0);
                assert_se(buf2_allocated >= k);
                assert_se(k == i);

                assert_se(memcmp(text, buf2, i) == 0);

                total += i;
                compressed += j;

                n2 = now(CLOCK_MONOTONIC);
                if (n2 - n > 60 * USEC_PER_SEC)
                        break;
        }

        dt = (n2-n) / 1e6;

        log_info("%s: compressed & decompressed %zu bytes in %.2fs (%.2fMiB/s), "
                 "mean compresion %.2f%%, skipped %zu bytes",
                 label, total, dt,
                 total / 1024. / 1024 / dt,
                 100 - compressed * 100. / total,
                 skipped);
}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);

#ifdef HAVE_XZ
        test_compress_decompress("XZ", compress_blob_xz, decompress_blob_xz);
#endif
#ifdef HAVE_LZ4
        test_compress_decompress("LZ4", compress_blob_lz4, decompress_blob_lz4);
#endif
        return 0;
}
