/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "argv-util.h"
#include "compress.h"
#include "parse-util.h"
#include "process-util.h"
#include "random-util.h"
#include "string-table.h"
#include "tests.h"
#include "time-util.h"

static usec_t arg_duration;
static size_t arg_start;

#define MAX_SIZE (1024*1024LU)
#define PRIME 1048571  /* A prime close enough to one megabyte that mod 4 == 3 */

typedef enum BenchmarkDataType {
        BENCHMARK_DATA_ZEROS,
        BENCHMARK_DATA_SIMPLE,
        BENCHMARK_DATA_RANDOM,
        _BENCHMARK_DATA_TYPE_MAX,
} BenchmarkDataType;

static const char* const benchmark_data_type_table[_BENCHMARK_DATA_TYPE_MAX] = {
        [BENCHMARK_DATA_ZEROS]  = "zeros",
        [BENCHMARK_DATA_SIMPLE] = "simple",
        [BENCHMARK_DATA_RANDOM] = "random",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(benchmark_data_type, BenchmarkDataType);

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

static char* make_buf(size_t count, BenchmarkDataType type) {
        char *buf;

        buf = malloc(count);
        ASSERT_NOT_NULL(buf);

        switch (type) {

        case BENCHMARK_DATA_ZEROS:
                memzero(buf, count);
                break;

        case BENCHMARK_DATA_SIMPLE:
                for (size_t i = 0; i < count; i++)
                        buf[i] = 'a' + i % ('z' - 'a' + 1);
                break;

        case BENCHMARK_DATA_RANDOM: {
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
                break;
        }

        default:
                assert_not_reached();
        }

        return buf;
}

TEST(benchmark) {
        for (BenchmarkDataType dt = 0; dt < _BENCHMARK_DATA_TYPE_MAX; dt++)
                for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                        if (c == COMPRESSION_NONE || !compression_supported(c))
                                continue;

                        const char *label = compression_to_string(c);
                        const char *type = benchmark_data_type_to_string(dt);
                        usec_t n, n2 = 0;

                        _cleanup_free_ char *text = NULL, *buf = NULL;
                        _cleanup_free_ void *buf2 = NULL;
                        size_t skipped = 0, compressed = 0, total = 0;

                        text = make_buf(MAX_SIZE, dt);
                        buf = calloc(MAX_SIZE + 1, 1);
                        ASSERT_NOT_NULL(text);
                        ASSERT_NOT_NULL(buf);

                        n = now(CLOCK_MONOTONIC);

                        for (size_t i = 0; i <= MAX_SIZE; i++) {
                                size_t j = 0, k = 0, size;
                                int r;

                                size = permute(i);
                                if (size == 0)
                                        continue;

                                log_debug("%s %zu %zu", type, i, size);

                                memzero(buf, MIN(size + 1000, MAX_SIZE));

                                r = compress_blob(c, text, size, buf, size, &j, /* level= */ -1);
                                /* assume compression must be successful except for small or random inputs */
                                ASSERT_TRUE(r >= 0 || (size < 2048 && r == -ENOBUFS) || dt == BENCHMARK_DATA_RANDOM);

                                /* check for overwrites */
                                ASSERT_EQ(buf[size], 0);
                                if (r < 0) {
                                        skipped += size;
                                        continue;
                                }

                                ASSERT_TRUE(j > 0);
                                if (j >= size)
                                        log_error("%s \"compressed\" %zu -> %zu", label, size, j);

                                ASSERT_OK_ZERO(decompress_blob(c, buf, j, &buf2, &k, 0));
                                ASSERT_EQ(k, size);
                                ASSERT_EQ(memcmp(text, buf2, size), 0);

                                total += size;
                                compressed += j;

                                n2 = now(CLOCK_MONOTONIC);
                                if (n2 - n > arg_duration)
                                        break;
                        }

                        float elapsed = (n2-n) / 1e6;

                        log_info("%s/%s: compressed & decompressed %zu bytes in %.2fs (%.2fMiB/s), "
                                 "mean compression %.2f%%, skipped %zu bytes",
                                 label, type, total, elapsed,
                                 total / 1024. / 1024 / elapsed,
                                 100 - compressed * 100. / total,
                                 skipped);
                }
}

static int intro(void) {
        if (saved_argc >= 2) {
                unsigned x;

                ASSERT_OK(safe_atou(saved_argv[1], &x));
                arg_duration = x * USEC_PER_SEC;
        } else
                arg_duration = slow_tests_enabled() ?
                        2 * USEC_PER_SEC : USEC_PER_SEC / 50;

        if (saved_argc == 3)
                (void) safe_atozu(saved_argv[2], &arg_start);
        else
                arg_start = getpid_cached();

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
