/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LZ4
#include <lz4.h>
#endif

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "path-util.h"
#include "random-util.h"
#include "tests.h"
#include "util.h"

#if HAVE_XZ
# define XZ_OK 0
#else
# define XZ_OK -EPROTONOSUPPORT
#endif

#if HAVE_LZ4
# define LZ4_OK 0
#else
# define LZ4_OK -EPROTONOSUPPORT
#endif

typedef int (compress_blob_t)(const void *src, uint64_t src_size,
                              void *dst, size_t dst_alloc_size, size_t *dst_size);
typedef int (decompress_blob_t)(const void *src, uint64_t src_size,
                                void **dst, size_t *dst_alloc_size,
                                size_t* dst_size, size_t dst_max);
typedef int (decompress_sw_t)(const void *src, uint64_t src_size,
                              void **buffer, size_t *buffer_size,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra);

typedef int (compress_stream_t)(int fdf, int fdt, uint64_t max_bytes);
typedef int (decompress_stream_t)(int fdf, int fdt, uint64_t max_size);

#if HAVE_XZ || HAVE_LZ4
static void test_compress_decompress(int compression,
                                     compress_blob_t compress,
                                     decompress_blob_t decompress,
                                     const char *data,
                                     size_t data_len,
                                     bool may_fail) {
        char compressed[512];
        size_t csize, usize = 0;
        _cleanup_free_ char *decompressed = NULL;
        int r;

        log_info("/* testing %s %s blob compression/decompression */",
                 object_compressed_to_string(compression), data);

        r = compress(data, data_len, compressed, sizeof(compressed), &csize);
        if (r == -ENOBUFS) {
                log_info_errno(r, "compression failed: %m");
                assert_se(may_fail);
        } else {
                assert_se(r == 0);
                r = decompress(compressed, csize,
                               (void **) &decompressed, &usize, &csize, 0);
                assert_se(r == 0);
                assert_se(decompressed);
                assert_se(memcmp(decompressed, data, data_len) == 0);
        }

        r = decompress("garbage", 7,
                       (void **) &decompressed, &usize, &csize, 0);
        assert_se(r < 0);

        /* make sure to have the minimal lz4 compressed size */
        r = decompress("00000000\1g", 9,
                       (void **) &decompressed, &usize, &csize, 0);
        assert_se(r < 0);

        r = decompress("\100000000g", 9,
                       (void **) &decompressed, &usize, &csize, 0);
        assert_se(r < 0);

        memzero(decompressed, usize);
}

static void test_decompress_startswith(int compression,
                                       compress_blob_t compress,
                                       decompress_sw_t decompress_sw,
                                       const char *data,
                                       size_t data_len,
                                       bool may_fail) {

        char *compressed;
        _cleanup_free_ char *compressed1 = NULL, *compressed2 = NULL, *decompressed = NULL;
        size_t csize, usize = 0, len;
        int r;

        log_info("/* testing decompress_startswith with %s on %.20s text */",
                 object_compressed_to_string(compression), data);

#define BUFSIZE_1 512
#define BUFSIZE_2 20000

        compressed = compressed1 = malloc(BUFSIZE_1);
        assert_se(compressed1);
        r = compress(data, data_len, compressed, BUFSIZE_1, &csize);
        if (r == -ENOBUFS) {
                log_info_errno(r, "compression failed: %m");
                assert_se(may_fail);

                compressed = compressed2 = malloc(BUFSIZE_2);
                assert_se(compressed2);
                r = compress(data, data_len, compressed, BUFSIZE_2, &csize);
                assert(r == 0);
        }
        assert_se(r == 0);

        len = strlen(data);

        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, data, len, '\0');
        assert_se(r > 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, data, len, 'w');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, "barbarbar", 9, ' ');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, data, len - 1, data[len-1]);
        assert_se(r > 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, data, len - 1, 'w');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, &usize, data, len, '\0');
        assert_se(r > 0);
}

static void test_decompress_startswith_short(int compression,
                                             compress_blob_t compress,
                                             decompress_sw_t decompress_sw) {

#define TEXT "HUGE=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        char buf[1024];
        size_t i, csize;
        int r;

        log_info("/* %s with %s */", __func__, object_compressed_to_string(compression));

        r = compress(TEXT, sizeof TEXT, buf, sizeof buf, &csize);
        assert_se(r == 0);

        for (i = 1; i < strlen(TEXT); i++) {
                size_t alloc_size = i;
                _cleanup_free_ void *buf2 = NULL;

                assert_se(buf2 = malloc(i));

                assert_se(decompress_sw(buf, csize, &buf2, &alloc_size, TEXT, i, TEXT[i]) == 1);
                assert_se(decompress_sw(buf, csize, &buf2, &alloc_size, TEXT, i, 'y') == 0);
        }
}

static void test_compress_stream(int compression,
                                 const char* cat,
                                 compress_stream_t compress,
                                 decompress_stream_t decompress,
                                 const char *srcfile) {

        _cleanup_close_ int src = -1, dst = -1, dst2 = -1;
        _cleanup_(unlink_tempfilep) char
                pattern[] = "/tmp/systemd-test.compressed.XXXXXX",
                pattern2[] = "/tmp/systemd-test.compressed.XXXXXX";
        int r;
        _cleanup_free_ char *cmd = NULL, *cmd2 = NULL;
        struct stat st = {};

        r = find_binary(cat, NULL);
        if (r < 0) {
                log_error_errno(r, "Skipping %s, could not find %s binary: %m", __func__, cat);
                return;
        }

        log_debug("/* testing %s compression */",
                  object_compressed_to_string(compression));

        log_debug("/* create source from %s */", srcfile);

        assert_se((src = open(srcfile, O_RDONLY|O_CLOEXEC)) >= 0);

        log_debug("/* test compression */");

        assert_se((dst = mkostemp_safe(pattern)) >= 0);

        assert_se(compress(src, dst, -1) == 0);

        if (cat) {
                assert_se(asprintf(&cmd, "%s %s | diff %s -", cat, pattern, srcfile) > 0);
                assert_se(system(cmd) == 0);
        }

        log_debug("/* test decompression */");

        assert_se((dst2 = mkostemp_safe(pattern2)) >= 0);

        assert_se(stat(srcfile, &st) == 0);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        r = decompress(dst, dst2, st.st_size);
        assert_se(r == 0);

        assert_se(asprintf(&cmd2, "diff %s %s", srcfile, pattern2) > 0);
        assert_se(system(cmd2) == 0);

        log_debug("/* test faulty decompression */");

        assert_se(lseek(dst, 1, SEEK_SET) == 1);
        r = decompress(dst, dst2, st.st_size);
        assert_se(IN_SET(r, 0, -EBADMSG));

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        assert_se(lseek(dst2, 0, SEEK_SET) == 0);
        r = decompress(dst, dst2, st.st_size - 1);
        assert_se(r == -EFBIG);
}
#endif

#if HAVE_LZ4
static void test_lz4_decompress_partial(void) {
        char buf[20000], buf2[100];
        size_t buf_size = sizeof(buf), compressed;
        int r;
        _cleanup_free_ char *huge = NULL;

#define HUGE_SIZE (4096*1024)
        assert_se(huge = malloc(HUGE_SIZE));
        memset(huge, 'x', HUGE_SIZE);
        memcpy(huge, "HUGE=", 5);

        r = LZ4_compress_default(huge, buf, HUGE_SIZE, buf_size);
        assert_se(r >= 0);
        compressed = r;
        log_info("Compressed %i → %zu", HUGE_SIZE, compressed);

        r = LZ4_decompress_safe(buf, huge, r, HUGE_SIZE);
        assert_se(r >= 0);
        log_info("Decompressed → %i", r);

        r = LZ4_decompress_safe_partial(buf, huge,
                                        compressed,
                                        12, HUGE_SIZE);
        assert_se(r >= 0);
        log_info("Decompressed partial %i/%i → %i", 12, HUGE_SIZE, r);

        for (size_t size = 1; size < sizeof(buf2); size++) {
                /* This failed in older lz4s but works in newer ones. */
                r = LZ4_decompress_safe_partial(buf, buf2, compressed, size, size);
                log_info("Decompressed partial %zu/%zu → %i (%s)", size, size, r,
                                                                   r < 0 ? "bad" : "good");
                if (r >= 0 && LZ4_versionNumber() >= 10803)
                        /* lz4 <= 1.8.2 should fail that test, let's only check for newer ones */
                        assert_se(memcmp(buf2, huge, r) == 0);
        }
}
#endif

int main(int argc, char *argv[]) {
#if HAVE_XZ || HAVE_LZ4
        const char text[] =
                "text\0foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
                "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";

        /* The file to test compression on can be specified as the first argument */
        const char *srcfile = argc > 1 ? argv[1] : argv[0];

        char data[512] = "random\0";

        char huge[4096*1024];
        memset(huge, 'x', sizeof(huge));
        memcpy(huge, "HUGE=", 5);
        char_array_0(huge);

        test_setup_logging(LOG_DEBUG);

        random_bytes(data + 7, sizeof(data) - 7);

#if HAVE_XZ
        test_compress_decompress(OBJECT_COMPRESSED_XZ, compress_blob_xz, decompress_blob_xz,
                                 text, sizeof(text), false);
        test_compress_decompress(OBJECT_COMPRESSED_XZ, compress_blob_xz, decompress_blob_xz,
                                 data, sizeof(data), true);

        test_decompress_startswith(OBJECT_COMPRESSED_XZ,
                                   compress_blob_xz, decompress_startswith_xz,
                                   text, sizeof(text), false);
        test_decompress_startswith(OBJECT_COMPRESSED_XZ,
                                   compress_blob_xz, decompress_startswith_xz,
                                   data, sizeof(data), true);
        test_decompress_startswith(OBJECT_COMPRESSED_XZ,
                                   compress_blob_xz, decompress_startswith_xz,
                                   huge, sizeof(huge), true);

        test_compress_stream(OBJECT_COMPRESSED_XZ, "xzcat",
                             compress_stream_xz, decompress_stream_xz, srcfile);

        test_decompress_startswith_short(OBJECT_COMPRESSED_XZ, compress_blob_xz, decompress_startswith_xz);

#else
        log_info("/* XZ test skipped */");
#endif

#if HAVE_LZ4
        test_compress_decompress(OBJECT_COMPRESSED_LZ4, compress_blob_lz4, decompress_blob_lz4,
                                 text, sizeof(text), false);
        test_compress_decompress(OBJECT_COMPRESSED_LZ4, compress_blob_lz4, decompress_blob_lz4,
                                 data, sizeof(data), true);

        test_decompress_startswith(OBJECT_COMPRESSED_LZ4,
                                   compress_blob_lz4, decompress_startswith_lz4,
                                   text, sizeof(text), false);
        test_decompress_startswith(OBJECT_COMPRESSED_LZ4,
                                   compress_blob_lz4, decompress_startswith_lz4,
                                   data, sizeof(data), true);
        test_decompress_startswith(OBJECT_COMPRESSED_LZ4,
                                   compress_blob_lz4, decompress_startswith_lz4,
                                   huge, sizeof(huge), true);

        test_compress_stream(OBJECT_COMPRESSED_LZ4, "lz4cat",
                             compress_stream_lz4, decompress_stream_lz4, srcfile);

        test_lz4_decompress_partial();

        test_decompress_startswith_short(OBJECT_COMPRESSED_LZ4, compress_blob_lz4, decompress_startswith_lz4);

#else
        log_info("/* LZ4 test skipped */");
#endif

        return 0;
#else
        log_info("/* XZ and LZ4 tests skipped */");
        return EXIT_TEST_SKIP;
#endif
}
