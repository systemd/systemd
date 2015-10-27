/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "alloc-util.h"
#include "compress.h"
#include "macro.h"
#include "parse-util.h"
#include "random-util.h"
#include "string-util.h"
#include "util.h"

typedef int (compress_t)(const void *src, uint64_t src_size, void *dst, size_t *dst_size);
typedef int (decompress_t)(const void *src, uint64_t src_size,
                           void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);

static usec_t arg_duration = 2 * USEC_PER_SEC;
static size_t arg_start;

#define MAX_SIZE (1024*1024LU)
#define PRIME 1048571  /* A prime close enough to one megabyte that mod 4 == 3 */

static size_t _permute(size_t x) {
        size_t residue;

        if (x >= PRIME)
                return x;

        residue = x*x % PRIME;
        if (x <= PRIME / 2)
                return residue;
        else
                return PRIME - residue;
}

static size_t permute(size_t x) {
        return _permute((_permute(x) + arg_start) % MAX_SIZE ^ 0xFF345);
}

static char* make_buf(size_t count, const char *type) {
        char *buf;
        size_t i;

        buf = malloc(count);
        assert_se(buf);

        if (streq(type, "zeros"))
                memzero(buf, count);
        else if (streq(type, "simple"))
                for (i = 0; i < count; i++)
                        buf[i] = 'a' + i % ('z' - 'a' + 1);
        else if (streq(type, "random")) {
                size_t step = count / 10;

                random_bytes(buf, step);
                memzero(buf + 1*step, step);
                random_bytes(buf + 2*step, step);
                memzero(buf + 3*step, step);
                random_bytes(buf + 4*step, step);
                memzero(buf + 5*step, step);
                random_bytes(buf + 6*step, step);
                memzero(buf + 7*step, step);
                random_bytes(buf + 8*step, step);
                memzero(buf + 9*step, step);
        } else
                assert_not_reached("here");

        return buf;
}

static void test_compress_decompress(const char* label, const char* type,
                                     compress_t compress, decompress_t decompress) {
        usec_t n, n2 = 0;
        float dt;

        _cleanup_free_ char *text, *buf;
        _cleanup_free_ void *buf2 = NULL;
        size_t buf2_allocated = 0;
        size_t skipped = 0, compressed = 0, total = 0;

        text = make_buf(MAX_SIZE, type);
        buf = calloc(MAX_SIZE + 1, 1);
        assert_se(text && buf);

        n = now(CLOCK_MONOTONIC);

        for (size_t i = 0; i <= MAX_SIZE; i++) {
                size_t j = 0, k = 0, size;
                int r;

                size = permute(i);

                log_debug("%s %zu %zu", type, i, size);

                memzero(buf, MIN(size + 1000, MAX_SIZE));

                r = compress(text, size, buf, &j);
                /* assume compression must be successful except for small inputs */
                assert_se(r == 0 || (size < 2048 && r == -ENOBUFS) || streq(type, "random"));

                /* check for overwrites */
                assert_se(buf[size] == 0);
                if (r != 0) {
                        skipped += size;
                        continue;
                }

                assert_se(j > 0);
                if (j >= size)
                        log_error("%s \"compressed\" %zu -> %zu", label, size, j);

                r = decompress(buf, j, &buf2, &buf2_allocated, &k, 0);
                assert_se(r == 0);
                assert_se(buf2_allocated >= k);
                assert_se(k == size);

                assert_se(memcmp(text, buf2, size) == 0);

                total += size;
                compressed += j;

                n2 = now(CLOCK_MONOTONIC);
                if (n2 - n > arg_duration)
                        break;
        }

        dt = (n2-n) / 1e6;

        log_info("%s/%s: compressed & decompressed %zu bytes in %.2fs (%.2fMiB/s), "
                 "mean compresion %.2f%%, skipped %zu bytes",
                 label, type, total, dt,
                 total / 1024. / 1024 / dt,
                 100 - compressed * 100. / total,
                 skipped);
}

int main(int argc, char *argv[]) {
        const char *i;

        log_set_max_level(LOG_INFO);

        if (argc >= 2) {
                unsigned x;

                assert_se(safe_atou(argv[1], &x) >= 0);
                arg_duration = x * USEC_PER_SEC;
        }
        if (argc == 3)
                (void) safe_atolu(argv[2], &arg_start);
        else
                arg_start = getpid();

        NULSTR_FOREACH(i, "zeros\0simple\0random\0") {
#ifdef HAVE_XZ
                test_compress_decompress("XZ", i, compress_blob_xz, decompress_blob_xz);
#endif
#ifdef HAVE_LZ4
                test_compress_decompress("LZ4", i, compress_blob_lz4, decompress_blob_lz4);
#endif
        }
        return 0;
}
