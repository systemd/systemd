/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "compress.h"
#include "fd-util.h"
#include "io-util.h"
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

TEST(decompress_stream_sparse) {
        for (Compression c = 0; c < _COMPRESSION_MAX; c++) {
                if (c == COMPRESSION_NONE || !compression_supported(c))
                        continue;

                _cleanup_close_ int src = -EBADF, compressed = -EBADF, decompressed = -EBADF;
                _cleanup_(unlink_tempfilep) char
                        pattern_src[] = "/tmp/systemd-test.sparse-src.XXXXXX",
                        pattern_compressed[] = "/tmp/systemd-test.sparse-compressed.XXXXXX",
                        pattern_decompressed[] = "/tmp/systemd-test.sparse-decompressed.XXXXXX";
                /* Create a sparse-like input: 4K of data, 64K of zeros, 4K of data, 64K trailing zeros.
                 * Total apparent size: 136K, but most of it is zeros. */
                uint8_t data_block[4096];
                struct stat st_src, st_decompressed;
                uint64_t uncompressed_size;

                log_debug("/* testing %s sparse decompression */", compression_to_string(c));

                random_bytes(data_block, sizeof(data_block));

                ASSERT_OK(src = mkostemp_safe(pattern_src));

                /* Write: 4K data, 64K zeros, 4K data, 64K zeros */
                ASSERT_OK(loop_write(src, data_block, sizeof(data_block)));
                ASSERT_OK_ERRNO(ftruncate(src, sizeof(data_block) + 65536));
                ASSERT_OK_ERRNO(lseek(src, sizeof(data_block) + 65536, SEEK_SET));
                ASSERT_OK(loop_write(src, data_block, sizeof(data_block)));
                ASSERT_OK_ERRNO(ftruncate(src, 2 * sizeof(data_block) + 2 * 65536));
                ASSERT_EQ(lseek(src, 0, SEEK_SET), (off_t) 0);

                ASSERT_OK_ERRNO(fstat(src, &st_src));
                ASSERT_EQ(st_src.st_size, 2 * (off_t) sizeof(data_block) + 2 * 65536);

                /* Compress */
                ASSERT_OK(compressed = mkostemp_safe(pattern_compressed));
                ASSERT_OK(compress_stream(c, src, compressed, -1, &uncompressed_size));
                ASSERT_EQ((uint64_t) st_src.st_size, uncompressed_size);

                /* Decompress to a regular file (sparse writes auto-detected) */
                ASSERT_OK(decompressed = mkostemp_safe(pattern_decompressed));
                ASSERT_EQ(lseek(compressed, 0, SEEK_SET), (off_t) 0);
                ASSERT_OK_ZERO(decompress_stream(c, compressed, decompressed, st_src.st_size));

                /* Verify apparent size matches */
                ASSERT_OK_ERRNO(fstat(decompressed, &st_decompressed));
                ASSERT_EQ(st_decompressed.st_size, st_src.st_size);

                /* Verify content matches by comparing bytes */
                ASSERT_EQ(lseek(src, 0, SEEK_SET), (off_t) 0);
                ASSERT_EQ(lseek(decompressed, 0, SEEK_SET), (off_t) 0);

                for (off_t offset = 0; offset < st_src.st_size;) {
                        uint8_t buf_src[4096], buf_dst[4096];
                        size_t to_read = MIN((size_t) (st_src.st_size - offset), sizeof(buf_src));

                        ASSERT_EQ(loop_read(src, buf_src, to_read, true), (ssize_t) to_read);
                        ASSERT_EQ(loop_read(decompressed, buf_dst, to_read, true), (ssize_t) to_read);
                        ASSERT_EQ(memcmp(buf_src, buf_dst, to_read), 0);
                        offset += to_read;
                }

                /* Verify the decompressed file is actually sparse (uses less disk than apparent size).
                 * st_blocks is in 512-byte units. The file has 128K of zeros, so disk usage should be
                 * noticeably less than the apparent size if sparse writes worked.
                 * Only assert if the filesystem supports holes (SEEK_HOLE). */
                log_debug("%s sparse decompression: apparent=%jd disk=%jd",
                          compression_to_string(c),
                          (intmax_t) st_decompressed.st_size,
                          (intmax_t) st_decompressed.st_blocks * 512);
                if (lseek(decompressed, 0, SEEK_HOLE) < st_decompressed.st_size)
                        ASSERT_LT(st_decompressed.st_blocks * 512, st_decompressed.st_size);
                else
                        log_debug("Filesystem does not support holes, skipping sparsity check");

                /* Test all-zeros input: entire output should be a hole */
                log_debug("/* testing %s sparse decompression of all-zeros */", compression_to_string(c));
                {
                        _cleanup_close_ int zsrc = -EBADF, zcompressed = -EBADF, zdecompressed = -EBADF;
                        _cleanup_(unlink_tempfilep) char
                                zp_src[] = "/tmp/systemd-test.sparse-zero-src.XXXXXX",
                                zp_compressed[] = "/tmp/systemd-test.sparse-zero-compressed.XXXXXX",
                                zp_decompressed[] = "/tmp/systemd-test.sparse-zero-decompressed.XXXXXX";
                        struct stat zst;
                        uint64_t zsize;
                        uint8_t zeros[65536] = {};

                        ASSERT_OK(zsrc = mkostemp_safe(zp_src));
                        ASSERT_OK(loop_write(zsrc, zeros, sizeof(zeros)));
                        ASSERT_EQ(lseek(zsrc, 0, SEEK_SET), (off_t) 0);

                        ASSERT_OK(zcompressed = mkostemp_safe(zp_compressed));
                        ASSERT_OK(compress_stream(c, zsrc, zcompressed, -1, &zsize));
                        ASSERT_EQ(zsize, (uint64_t) sizeof(zeros));

                        ASSERT_OK(zdecompressed = mkostemp_safe(zp_decompressed));
                        ASSERT_EQ(lseek(zcompressed, 0, SEEK_SET), (off_t) 0);
                        ASSERT_OK_ZERO(decompress_stream(c, zcompressed, zdecompressed, sizeof(zeros)));

                        ASSERT_OK_ERRNO(fstat(zdecompressed, &zst));
                        ASSERT_EQ(zst.st_size, (off_t) sizeof(zeros));
                        /* All zeros — disk usage should be minimal */
                        log_debug("%s all-zeros sparse: apparent=%jd disk=%jd",
                                  compression_to_string(c), (intmax_t) zst.st_size, (intmax_t) zst.st_blocks * 512);
                        if (lseek(zdecompressed, 0, SEEK_HOLE) < zst.st_size)
                                ASSERT_LT(zst.st_blocks * 512, zst.st_size);
                        else
                                log_debug("Filesystem does not support holes, skipping sparsity check");
                }

                /* Test data ending with non-zero bytes: ftruncate should be a no-op */
                log_debug("/* testing %s sparse decompression ending with data */", compression_to_string(c));
                {
                        _cleanup_close_ int dsrc = -EBADF, dcompressed = -EBADF, ddecompressed = -EBADF;
                        _cleanup_(unlink_tempfilep) char
                                dp_src[] = "/tmp/systemd-test.sparse-end-src.XXXXXX",
                                dp_compressed[] = "/tmp/systemd-test.sparse-end-compressed.XXXXXX",
                                dp_decompressed[] = "/tmp/systemd-test.sparse-end-decompressed.XXXXXX";
                        struct stat dst;
                        uint64_t dsize;
                        uint8_t zeros[65536] = {};

                        /* 64K zeros followed by 4K random data */
                        ASSERT_OK(dsrc = mkostemp_safe(dp_src));
                        ASSERT_OK(loop_write(dsrc, zeros, sizeof(zeros)));
                        ASSERT_OK(loop_write(dsrc, data_block, sizeof(data_block)));
                        ASSERT_EQ(lseek(dsrc, 0, SEEK_SET), (off_t) 0);

                        ASSERT_OK(dcompressed = mkostemp_safe(dp_compressed));
                        ASSERT_OK(compress_stream(c, dsrc, dcompressed, -1, &dsize));
                        ASSERT_EQ(dsize, (uint64_t)(sizeof(zeros) + sizeof(data_block)));

                        ASSERT_OK(ddecompressed = mkostemp_safe(dp_decompressed));
                        ASSERT_EQ(lseek(dcompressed, 0, SEEK_SET), (off_t) 0);
                        ASSERT_OK_ZERO(decompress_stream(c, dcompressed, ddecompressed, dsize));

                        ASSERT_OK_ERRNO(fstat(ddecompressed, &dst));
                        ASSERT_EQ(dst.st_size, (off_t)(sizeof(zeros) + sizeof(data_block)));
                }
        }
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
