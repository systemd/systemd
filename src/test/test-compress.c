/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "compress.h"
#include "fd-util.h"
#include "path-util.h"
#include "random-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define HUGE_SIZE (4096*1024)

static const char text[] =
        "text\0foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
        "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";
static char data[512] = "random\0";
static char *huge = NULL;
static const char *srcfile;

static const char* cat_for_compression(Compression c) {
        switch (c) {
        case COMPRESSION_XZ:    return "xzcat";
        case COMPRESSION_LZ4:   return "lz4cat";
        case COMPRESSION_ZSTD:  return "zstdcat";
        case COMPRESSION_GZIP:  return "zcat";
        case COMPRESSION_BZIP2: return "bzcat";
        default:                return NULL;
        }
}

TEST(compress_decompress_blob) {
        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                const char *label = compression_to_string(c);

                for (size_t t = 0; t < 2; t++) {
                        const char *input = t == 0 ? text : data;
                        size_t input_len = t == 0 ? sizeof(text) : sizeof(data);
                        bool may_fail = t == 1;

                        char compressed[512];
                        size_t csize;
                        _cleanup_free_ char *decompressed = NULL;
                        int r;

                        log_info("/* testing %s %s blob compression/decompression */", label, input);

                        r = compress_blob(c, input, input_len, compressed, sizeof(compressed), &csize, -1);
                        if (r == -ENOBUFS) {
                                log_info_errno(r, "compression failed: %m");
                                ASSERT_TRUE(may_fail);
                        } else {
                                ASSERT_OK(r);
                                ASSERT_OK_ZERO(decompress_blob(c, compressed, csize, (void **) &decompressed, &csize, 0));
                                ASSERT_NOT_NULL(decompressed);
                                ASSERT_EQ(memcmp(decompressed, input, input_len), 0);
                        }

                        ASSERT_FAIL(decompress_blob(c, "garbage", 7, (void **) &decompressed, &csize, 0));
                }
        }
}

TEST(decompress_startswith) {
        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                const char *label = compression_to_string(c);

                struct { const char *buf; size_t len; bool may_fail; } inputs[] = {
                        { text, sizeof(text), false },
                        { data, sizeof(data), true  },
                        { huge, HUGE_SIZE,    true  },
                };

                for (size_t t = 0; t < ELEMENTSOF(inputs); t++) {
                        char *compressed;
                        _cleanup_free_ char *compressed1 = NULL, *compressed2 = NULL, *decompressed = NULL;
                        size_t csize, len;
                        int r;

                        log_info("/* testing decompress_startswith with %s on %.20s */", label, inputs[t].buf);

                        compressed = compressed1 = malloc(512);
                        ASSERT_NOT_NULL(compressed1);
                        r = compress_blob(c, inputs[t].buf, inputs[t].len, compressed, 512, &csize, -1);
                        if (r == -ENOBUFS) {
                                log_info_errno(r, "compression failed: %m");
                                ASSERT_TRUE(inputs[t].may_fail);

                                compressed = compressed2 = malloc(20000);
                                ASSERT_NOT_NULL(compressed2);
                                r = compress_blob(c, inputs[t].buf, inputs[t].len, compressed, 20000, &csize, -1);
                        }
                        if (r == -ENOBUFS) {
                                log_info_errno(r, "compression failed again: %m");
                                ASSERT_TRUE(inputs[t].may_fail);
                                continue;
                        }
                        ASSERT_OK(r);

                        len = strlen(inputs[t].buf);

                        ASSERT_OK_POSITIVE(decompress_startswith(c, compressed, csize, (void **) &decompressed, inputs[t].buf, len, '\0'));
                        ASSERT_OK_ZERO(decompress_startswith(c, compressed, csize, (void **) &decompressed, inputs[t].buf, len, 'w'));
                        ASSERT_OK_POSITIVE(decompress_startswith(c, compressed, csize, (void **) &decompressed, inputs[t].buf, len - 1, inputs[t].buf[len-1]));
                        ASSERT_OK_ZERO(decompress_startswith(c, compressed, csize, (void **) &decompressed, inputs[t].buf, len - 1, 'w'));
                }
        }
}

TEST(decompress_startswith_large) {
        /* Test decompress_startswith with large data to exercise the buffer growth path. */

        _cleanup_free_ char *large = NULL;
        size_t large_size = 8 * 1024;

        ASSERT_NOT_NULL(large = malloc(large_size));
        for (size_t i = 0; i < large_size; i++)
                large[i] = 'A' + (i % 26);

        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                _cleanup_free_ char *compressed = NULL;
                size_t csize;

                log_info("/* decompress_startswith_large with %s */", compression_to_string(c));

                ASSERT_NOT_NULL(compressed = malloc(large_size));
                int r = compress_blob(c, large, large_size, compressed, large_size, &csize, -1);
                if (r == -ENOBUFS) {
                        log_info_errno(r, "compression failed: %m");
                        continue;
                }
                ASSERT_OK(r);

                _cleanup_free_ void *buf = NULL;

                ASSERT_OK_POSITIVE(decompress_startswith(c, compressed, csize, &buf, large, 1, large[1]));
                ASSERT_OK_ZERO(decompress_startswith(c, compressed, csize, &buf, large, 1, 0xff));
                ASSERT_OK_POSITIVE(decompress_startswith(c, compressed, csize, &buf, large, 512, large[512]));
                ASSERT_OK_ZERO(decompress_startswith(c, compressed, csize, &buf, large, 512, 0xff));
                ASSERT_OK_POSITIVE(decompress_startswith(c, compressed, csize, &buf, large, 4096, large[4096]));
                ASSERT_OK_ZERO(decompress_startswith(c, compressed, csize, &buf, large, 4096, 0xff));
        }
}

TEST(decompress_startswith_short) {
#define TEXT "HUGE=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                char buf[1024];
                size_t csize;

                log_info("/* decompress_startswith_short with %s */", compression_to_string(c));

                ASSERT_OK(compress_blob(c, TEXT, sizeof TEXT, buf, sizeof buf, &csize, -1));

                for (size_t i = 1; i < strlen(TEXT); i++) {
                        _cleanup_free_ void *buf2 = NULL;

                        ASSERT_NOT_NULL(buf2 = malloc(i));

                        ASSERT_OK_POSITIVE(decompress_startswith(c, buf, csize, &buf2, TEXT, i, TEXT[i]));
                        ASSERT_OK_ZERO(decompress_startswith(c, buf, csize, &buf2, TEXT, i, 'y'));
                }
        }
#undef TEXT
}

TEST(compress_decompress_stream) {
        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                const char *cat = cat_for_compression(c);
                if (!cat)
                        continue;

                int r = find_executable(cat, NULL);
                if (r < 0) {
                        log_error_errno(r, "Skipping %s, could not find %s binary: %m",
                                        compression_to_string(c), cat);
                        continue;
                }

                _cleanup_close_ int src = -EBADF, dst = -EBADF, dst2 = -EBADF;
                _cleanup_(unlink_tempfilep) char
                        pattern[] = "/tmp/systemd-test.compressed.XXXXXX",
                        pattern2[] = "/tmp/systemd-test.compressed.XXXXXX";
                _cleanup_free_ char *cmd = NULL, *cmd2 = NULL;
                struct stat st = {};
                uint64_t uncompressed_size;

                log_debug("/* testing %s stream compression */", compression_to_string(c));

                ASSERT_OK(src = open(srcfile, O_RDONLY|O_CLOEXEC));
                ASSERT_OK(dst = mkostemp_safe(pattern));

                ASSERT_OK(compress_stream(c, src, dst, -1, &uncompressed_size));

                ASSERT_OK_POSITIVE(asprintf(&cmd, "%s %s | diff '%s' -", cat, pattern, srcfile));
                ASSERT_OK_ZERO(system(cmd));

                ASSERT_OK(dst2 = mkostemp_safe(pattern2));

                ASSERT_OK_ZERO_ERRNO(stat(srcfile, &st));
                ASSERT_EQ((uint64_t) st.st_size, uncompressed_size);

                ASSERT_OK_ERRNO(lseek(dst, 0, SEEK_SET));
                ASSERT_OK_ZERO(decompress_stream(c, dst, dst2, st.st_size));

                ASSERT_OK_POSITIVE(asprintf(&cmd2, "diff '%s' %s", srcfile, pattern2));
                ASSERT_OK_ZERO(system(cmd2));

                log_debug("/* test faulty decompression */");

                ASSERT_OK_ERRNO(lseek(dst, 1, SEEK_SET));
                r = decompress_stream(c, dst, dst2, st.st_size);
                ASSERT_TRUE(IN_SET(r, 0, -EBADMSG));

                ASSERT_OK_ERRNO(lseek(dst, 0, SEEK_SET));
                ASSERT_OK_ERRNO(lseek(dst2, 0, SEEK_SET));
                ASSERT_ERROR(decompress_stream(c, dst, dst2, st.st_size - 1), EFBIG);
        }
}

struct decompressor_test_data {
        uint8_t *buf;
        size_t size;
};

static int test_decompressor_callback(const void *p, size_t size, void *userdata) {
        struct decompressor_test_data *d = ASSERT_PTR(userdata);

        if (!GREEDY_REALLOC(d->buf, d->size + size))
                return -ENOMEM;

        memcpy(d->buf + d->size, p, size);
        d->size += size;
        return 0;
}

TEST(compressor_decompressor_push_api) {
        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                log_info("/* testing %s Compressor/Decompressor push API */", compression_to_string(c));

                _cleanup_(compressor_freep) Compressor *compressor = NULL;
                _cleanup_(compressor_freep) Decompressor *decompressor = NULL;
                _cleanup_free_ void *compressed = NULL, *finish_buf = NULL;
                size_t compressed_size = 0, compressed_alloc = 0;
                size_t finish_size = 0, finish_alloc = 0;

                /* Compress */
                ASSERT_OK(compressor_new(&compressor, c));
                ASSERT_EQ(compressor_type(compressor), c);

                ASSERT_OK(compressor_start(compressor, text, sizeof(text), &compressed, &compressed_size, &compressed_alloc));
                ASSERT_OK(compressor_finish(compressor, &finish_buf, &finish_size, &finish_alloc));

                size_t total_compressed = compressed_size + finish_size;
                _cleanup_free_ void *full_compressed = malloc(total_compressed);
                ASSERT_NOT_NULL(full_compressed);
                memcpy(full_compressed, compressed, compressed_size);
                if (finish_size > 0)
                        memcpy((uint8_t*) full_compressed + compressed_size, finish_buf, finish_size);

                compressor = compressor_free(compressor);

                /* Decompress via detect + push and verify content */
                ASSERT_OK_POSITIVE(decompressor_detect(&decompressor, full_compressed, total_compressed));
                ASSERT_EQ(compressor_type(decompressor), c);

                struct decompressor_test_data result = {};
                ASSERT_OK(decompressor_push(decompressor, full_compressed, total_compressed, test_decompressor_callback, &result));
                ASSERT_EQ(result.size, sizeof(text));
                ASSERT_EQ(memcmp(result.buf, text, sizeof(text)), 0);
                free(result.buf);

                decompressor = compressor_free(decompressor);
        }

        /* Test compressor_type on NULL */
        ASSERT_EQ(compressor_type(NULL), _COMPRESSION_INVALID);

        /* Test decompressor_force_off */
        _cleanup_(compressor_freep) Decompressor *d = NULL;
        ASSERT_OK(decompressor_force_off(&d));
        ASSERT_EQ(compressor_type(d), COMPRESSION_NONE);
        d = compressor_free(d);

        /* Test decompressor_detect returning 0 on too-small input */
        ASSERT_OK_ZERO(decompressor_detect(&d, "x", 1));
        ASSERT_NULL(d);
}

static int intro(void) {
        srcfile = saved_argc > 1 ? saved_argv[1] : saved_argv[0];

        ASSERT_NOT_NULL(huge = malloc(HUGE_SIZE));
        memcpy(huge, "HUGE=", STRLEN("HUGE="));
        memset(&huge[STRLEN("HUGE=")], 'x', HUGE_SIZE - STRLEN("HUGE=") - 1);
        huge[HUGE_SIZE - 1] = '\0';

        random_bytes(data + 7, sizeof(data) - 7);

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
