/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#if HAVE_LZ4
#include <lz4.h>
#endif

#include "alloc-util.h"
#include "compress.h"
#include "dlfcn-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "path-util.h"
#include "random-util.h"
#include "tests.h"
#include "tmpfile-util.h"

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

#define HUGE_SIZE (4096*1024)

typedef int (compress_blob_t)(const void *src, uint64_t src_size,
                              void *dst, size_t dst_alloc_size, size_t *dst_size, int level);
typedef int (decompress_blob_t)(const void *src, uint64_t src_size,
                                void **dst,
                                size_t* dst_size, size_t dst_max);
typedef int (decompress_sw_t)(const void *src, uint64_t src_size,
                              void **buffer,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra);

typedef int (compress_stream_t)(int fdf, int fdt, uint64_t max_bytes, uint64_t *uncompressed_size);
typedef int (decompress_stream_t)(int fdf, int fdt, uint64_t max_size);

#if HAVE_COMPRESSION
_unused_ static void test_compress_decompress(
                const char *compression,
                compress_blob_t compress,
                decompress_blob_t decompress,
                const char *data,
                size_t data_len,
                bool may_fail) {

        char compressed[512];
        size_t csize;
        _cleanup_free_ char *decompressed = NULL;
        int r;

        log_info("/* testing %s %s blob compression/decompression */",
                 compression, data);

        r = compress(data, data_len, compressed, sizeof(compressed), &csize, /* level= */ -1);
        if (r == -ENOBUFS) {
                log_info_errno(r, "compression failed: %m");
                assert_se(may_fail);
        } else {
                assert_se(r >= 0);
                r = decompress(compressed, csize,
                               (void **) &decompressed, &csize, 0);
                assert_se(r == 0);
                assert_se(decompressed);
                assert_se(memcmp(decompressed, data, data_len) == 0);
        }

        r = decompress("garbage", 7,
                       (void **) &decompressed, &csize, 0);
        assert_se(r < 0);

        /* make sure to have the minimal lz4 compressed size */
        r = decompress("00000000\1g", 9,
                       (void **) &decompressed, &csize, 0);
        assert_se(r < 0);

        r = decompress("\100000000g", 9,
                       (void **) &decompressed, &csize, 0);
        assert_se(r < 0);

        explicit_bzero_safe(decompressed, MALLOC_SIZEOF_SAFE(decompressed));
}

_unused_ static void test_decompress_startswith(const char *compression,
                                                compress_blob_t compress,
                                                decompress_sw_t decompress_sw,
                                                const char *data,
                                                size_t data_len,
                                                bool may_fail) {

        char *compressed;
        _cleanup_free_ char *compressed1 = NULL, *compressed2 = NULL, *decompressed = NULL;
        size_t csize, len;
        int r;

        log_info("/* testing decompress_startswith with %s on %.20s text */",
                 compression, data);

#define BUFSIZE_1 512
#define BUFSIZE_2 20000

        compressed = compressed1 = malloc(BUFSIZE_1);
        assert_se(compressed1);
        r = compress(data, data_len, compressed, BUFSIZE_1, &csize, /* level= */ -1);
        if (r == -ENOBUFS) {
                log_info_errno(r, "compression failed: %m");
                assert_se(may_fail);

                compressed = compressed2 = malloc(BUFSIZE_2);
                assert_se(compressed2);
                r = compress(data, data_len, compressed, BUFSIZE_2, &csize, /* level= */ -1);
        }
        assert_se(r >= 0);

        len = strlen(data);

        r = decompress_sw(compressed, csize, (void **) &decompressed, data, len, '\0');
        assert_se(r > 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, data, len, 'w');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, "barbarbar", 9, ' ');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, data, len - 1, data[len-1]);
        assert_se(r > 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, data, len - 1, 'w');
        assert_se(r == 0);
        r = decompress_sw(compressed, csize, (void **) &decompressed, data, len, '\0');
        assert_se(r > 0);
}

_unused_ static void test_decompress_startswith_short(const char *compression,
                                                      compress_blob_t compress,
                                                      decompress_sw_t decompress_sw) {

#define TEXT "HUGE=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        char buf[1024];
        size_t csize;
        int r;

        log_info("/* %s with %s */", __func__, compression);

        r = compress(TEXT, sizeof TEXT, buf, sizeof buf, &csize, /* level= */ -1);
        assert_se(r >= 0);

        for (size_t i = 1; i < strlen(TEXT); i++) {
                _cleanup_free_ void *buf2 = NULL;

                assert_se(buf2 = malloc(i));

                assert_se(decompress_sw(buf, csize, &buf2, TEXT, i, TEXT[i]) == 1);
                assert_se(decompress_sw(buf, csize, &buf2, TEXT, i, 'y') == 0);
        }
}

_unused_ static void test_compress_stream(const char *compression,
                                          const char *cat,
                                          compress_stream_t compress,
                                          decompress_stream_t decompress,
                                          const char *srcfile) {

        _cleanup_close_ int src = -EBADF, dst = -EBADF, dst2 = -EBADF;
        _cleanup_(unlink_tempfilep) char
                pattern[] = "/tmp/systemd-test.compressed.XXXXXX",
                pattern2[] = "/tmp/systemd-test.compressed.XXXXXX";
        int r;
        _cleanup_free_ char *cmd = NULL, *cmd2 = NULL;
        struct stat st = {};
        uint64_t uncompressed_size;

        r = find_executable(cat, NULL);
        if (r < 0) {
                log_error_errno(r, "Skipping %s, could not find %s binary: %m", __func__, cat);
                return;
        }

        log_debug("/* testing %s compression */", compression);

        log_debug("/* create source from %s */", srcfile);

        ASSERT_OK(src = open(srcfile, O_RDONLY|O_CLOEXEC));

        log_debug("/* test compression */");

        assert_se((dst = mkostemp_safe(pattern)) >= 0);

        ASSERT_OK(compress(src, dst, -1, &uncompressed_size));

        if (cat) {
                assert_se(asprintf(&cmd, "%s %s | diff '%s' -", cat, pattern, srcfile) > 0);
                assert_se(system(cmd) == 0);
        }

        log_debug("/* test decompression */");

        assert_se((dst2 = mkostemp_safe(pattern2)) >= 0);

        assert_se(stat(srcfile, &st) == 0);
        assert_se((uint64_t)st.st_size == uncompressed_size);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        r = decompress(dst, dst2, st.st_size);
        assert_se(r == 0);

        assert_se(asprintf(&cmd2, "diff '%s' %s", srcfile, pattern2) > 0);
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

_unused_ static void test_decompress_stream_sparse(const char *compression,
                                                   compress_stream_t compress,
                                                   decompress_stream_t decompress) {

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
        int r;

        assert(compression);

        log_debug("/* testing %s sparse decompression */", compression);

        random_bytes(data_block, sizeof(data_block));

        assert_se((src = mkostemp_safe(pattern_src)) >= 0);

        /* Write: 4K data, 64K zeros, 4K data, 64K zeros */
        assert_se(loop_write(src, data_block, sizeof(data_block)) >= 0);
        assert_se(ftruncate(src, sizeof(data_block) + 65536) >= 0);
        assert_se(lseek(src, sizeof(data_block) + 65536, SEEK_SET) >= 0);
        assert_se(loop_write(src, data_block, sizeof(data_block)) >= 0);
        assert_se(ftruncate(src, 2 * sizeof(data_block) + 2 * 65536) >= 0);
        assert_se(lseek(src, 0, SEEK_SET) == 0);

        assert_se(fstat(src, &st_src) >= 0);
        assert_se(st_src.st_size == 2 * (off_t) sizeof(data_block) + 2 * 65536);

        /* Compress */
        assert_se((compressed = mkostemp_safe(pattern_compressed)) >= 0);
        ASSERT_OK(compress(src, compressed, -1, &uncompressed_size));
        assert_se((uint64_t) st_src.st_size == uncompressed_size);

        /* Decompress to a regular file (sparse writes auto-detected) */
        assert_se((decompressed = mkostemp_safe(pattern_decompressed)) >= 0);
        assert_se(lseek(compressed, 0, SEEK_SET) == 0);
        r = decompress(compressed, decompressed, st_src.st_size);
        assert_se(r == 0);

        /* Verify apparent size matches */
        assert_se(fstat(decompressed, &st_decompressed) >= 0);
        assert_se(st_decompressed.st_size == st_src.st_size);

        /* Verify content matches by comparing bytes */
        assert_se(lseek(src, 0, SEEK_SET) == 0);
        assert_se(lseek(decompressed, 0, SEEK_SET) == 0);

        for (off_t offset = 0; offset < st_src.st_size;) {
                uint8_t buf_src[4096], buf_dst[4096];
                size_t to_read = MIN((size_t) (st_src.st_size - offset), sizeof(buf_src));
                ssize_t n;

                n = loop_read(src, buf_src, to_read, true);
                assert_se(n == (ssize_t) to_read);
                n = loop_read(decompressed, buf_dst, to_read, true);
                assert_se(n == (ssize_t) to_read);
                assert_se(memcmp(buf_src, buf_dst, to_read) == 0);
                offset += to_read;
        }

        /* Verify the decompressed file is actually sparse (uses less disk than apparent size).
         * st_blocks is in 512-byte units. The file has 128K of zeros, so disk usage should be
         * noticeably less than the apparent size if sparse writes worked.
         * Only assert if the filesystem supports holes (SEEK_HOLE). */
        log_debug("%s sparse decompression: apparent=%jd disk=%jd",
                  compression,
                  (intmax_t) st_decompressed.st_size,
                  (intmax_t) st_decompressed.st_blocks * 512);
        if (lseek(decompressed, 0, SEEK_HOLE) < st_decompressed.st_size)
                assert_se(st_decompressed.st_blocks * 512 < st_decompressed.st_size);
        else
                log_debug("Filesystem does not support holes, skipping sparsity check");

        /* Test all-zeros input: entire output should be a hole */
        log_debug("/* testing %s sparse decompression of all-zeros */", compression);
        {
                _cleanup_close_ int zsrc = -EBADF, zcompressed = -EBADF, zdecompressed = -EBADF;
                _cleanup_(unlink_tempfilep) char
                        zp_src[] = "/tmp/systemd-test.sparse-zero-src.XXXXXX",
                        zp_compressed[] = "/tmp/systemd-test.sparse-zero-compressed.XXXXXX",
                        zp_decompressed[] = "/tmp/systemd-test.sparse-zero-decompressed.XXXXXX";
                struct stat zst;
                uint64_t zsize;
                uint8_t zeros[65536] = {};

                assert_se((zsrc = mkostemp_safe(zp_src)) >= 0);
                assert_se(loop_write(zsrc, zeros, sizeof(zeros)) >= 0);
                assert_se(lseek(zsrc, 0, SEEK_SET) == 0);

                assert_se((zcompressed = mkostemp_safe(zp_compressed)) >= 0);
                ASSERT_OK(compress(zsrc, zcompressed, -1, &zsize));
                assert_se(zsize == sizeof(zeros));

                assert_se((zdecompressed = mkostemp_safe(zp_decompressed)) >= 0);
                assert_se(lseek(zcompressed, 0, SEEK_SET) == 0);
                assert_se(decompress(zcompressed, zdecompressed, sizeof(zeros)) == 0);

                assert_se(fstat(zdecompressed, &zst) >= 0);
                assert_se(zst.st_size == (off_t) sizeof(zeros));
                /* All zeros — disk usage should be minimal */
                log_debug("%s all-zeros sparse: apparent=%jd disk=%jd",
                          compression, (intmax_t) zst.st_size, (intmax_t) zst.st_blocks * 512);
                if (lseek(zdecompressed, 0, SEEK_HOLE) < zst.st_size)
                        assert_se(zst.st_blocks * 512 < zst.st_size);
                else
                        log_debug("Filesystem does not support holes, skipping sparsity check");
        }

        /* Test data ending with non-zero bytes: ftruncate should be a no-op */
        log_debug("/* testing %s sparse decompression ending with data */", compression);
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
                assert_se((dsrc = mkostemp_safe(dp_src)) >= 0);
                assert_se(loop_write(dsrc, zeros, sizeof(zeros)) >= 0);
                assert_se(loop_write(dsrc, data_block, sizeof(data_block)) >= 0);
                assert_se(lseek(dsrc, 0, SEEK_SET) == 0);

                assert_se((dcompressed = mkostemp_safe(dp_compressed)) >= 0);
                ASSERT_OK(compress(dsrc, dcompressed, -1, &dsize));
                assert_se(dsize == sizeof(zeros) + sizeof(data_block));

                assert_se((ddecompressed = mkostemp_safe(dp_decompressed)) >= 0);
                assert_se(lseek(dcompressed, 0, SEEK_SET) == 0);
                assert_se(decompress(dcompressed, ddecompressed, dsize) == 0);

                assert_se(fstat(ddecompressed, &dst) >= 0);
                assert_se(dst.st_size == (off_t)(sizeof(zeros) + sizeof(data_block)));
        }
}
#endif

#if HAVE_LZ4
extern DLSYM_PROTOTYPE(LZ4_compress_default);
extern DLSYM_PROTOTYPE(LZ4_decompress_safe);
extern DLSYM_PROTOTYPE(LZ4_decompress_safe_partial);
extern DLSYM_PROTOTYPE(LZ4_versionNumber);

static void test_lz4_decompress_partial(void) {
        char buf[20000], buf2[100];
        size_t buf_size = sizeof(buf), compressed;
        int r;
        _cleanup_free_ char *huge = NULL;

        log_debug("/* %s */", __func__);

        assert_se(huge = malloc(HUGE_SIZE));
        memcpy(huge, "HUGE=", STRLEN("HUGE="));
        memset(&huge[STRLEN("HUGE=")], 'x', HUGE_SIZE - STRLEN("HUGE=") - 1);
        huge[HUGE_SIZE - 1] = '\0';

        r = sym_LZ4_compress_default(huge, buf, HUGE_SIZE, buf_size);
        assert_se(r >= 0);
        compressed = r;
        log_info("Compressed %i → %zu", HUGE_SIZE, compressed);

        r = sym_LZ4_decompress_safe(buf, huge, r, HUGE_SIZE);
        assert_se(r >= 0);
        log_info("Decompressed → %i", r);

        r = sym_LZ4_decompress_safe_partial(buf, huge,
                                        compressed,
                                        12, HUGE_SIZE);
        assert_se(r >= 0);
        log_info("Decompressed partial %i/%i → %i", 12, HUGE_SIZE, r);

        for (size_t size = 1; size < sizeof(buf2); size++) {
                /* This failed in older lz4s but works in newer ones. */
                r = sym_LZ4_decompress_safe_partial(buf, buf2, compressed, size, size);
                log_info("Decompressed partial %zu/%zu → %i (%s)", size, size, r,
                                                                   r < 0 ? "bad" : "good");
                if (r >= 0 && sym_LZ4_versionNumber() >= 10803)
                        /* lz4 <= 1.8.2 should fail that test, let's only check for newer ones */
                        assert_se(memcmp(buf2, huge, r) == 0);
        }
}
#endif

int main(int argc, char *argv[]) {
#if HAVE_COMPRESSION
        _unused_ const char text[] =
                "text\0foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
                "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";

        /* The file to test compression on can be specified as the first argument */
        const char *srcfile = argc > 1 ? argv[1] : argv[0];

        char data[512] = "random\0";

        _cleanup_free_ char *huge = NULL;

        assert_se(huge = malloc(HUGE_SIZE));
        memcpy(huge, "HUGE=", STRLEN("HUGE="));
        memset(&huge[STRLEN("HUGE=")], 'x', HUGE_SIZE - STRLEN("HUGE=") - 1);
        huge[HUGE_SIZE - 1] = '\0';

        test_setup_logging(LOG_DEBUG);

        random_bytes(data + 7, sizeof(data) - 7);

#if HAVE_XZ
        test_compress_decompress("XZ", compress_blob_xz, decompress_blob_xz,
                                 text, sizeof(text), false);
        test_compress_decompress("XZ", compress_blob_xz, decompress_blob_xz,
                                 data, sizeof(data), true);

        test_decompress_startswith("XZ",
                                   compress_blob_xz, decompress_startswith_xz,
                                   text, sizeof(text), false);
        test_decompress_startswith("XZ",
                                   compress_blob_xz, decompress_startswith_xz,
                                   data, sizeof(data), true);
        test_decompress_startswith("XZ",
                                   compress_blob_xz, decompress_startswith_xz,
                                   huge, HUGE_SIZE, true);

        test_compress_stream("XZ", "xzcat",
                             compress_stream_xz, decompress_stream_xz, srcfile);

        test_decompress_stream_sparse("XZ", compress_stream_xz, decompress_stream_xz);

        test_decompress_startswith_short("XZ", compress_blob_xz, decompress_startswith_xz);

#else
        log_info("/* XZ test skipped */");
#endif

#if HAVE_LZ4
        if (dlopen_lz4() >= 0) {
                test_compress_decompress("LZ4", compress_blob_lz4, decompress_blob_lz4,
                                         text, sizeof(text), false);
                test_compress_decompress("LZ4", compress_blob_lz4, decompress_blob_lz4,
                                         data, sizeof(data), true);

                test_decompress_startswith("LZ4",
                                           compress_blob_lz4, decompress_startswith_lz4,
                                           text, sizeof(text), false);
                test_decompress_startswith("LZ4",
                                           compress_blob_lz4, decompress_startswith_lz4,
                                           data, sizeof(data), true);
                test_decompress_startswith("LZ4",
                                           compress_blob_lz4, decompress_startswith_lz4,
                                           huge, HUGE_SIZE, true);

                test_compress_stream("LZ4", "lz4cat",
                                     compress_stream_lz4, decompress_stream_lz4, srcfile);

                test_decompress_stream_sparse("LZ4", compress_stream_lz4, decompress_stream_lz4);

                test_lz4_decompress_partial();

                test_decompress_startswith_short("LZ4", compress_blob_lz4, decompress_startswith_lz4);
        } else
                log_error("/* Can't load liblz4 */");
#else
        log_info("/* LZ4 test skipped */");
#endif

#if HAVE_ZSTD
        test_compress_decompress("ZSTD", compress_blob_zstd, decompress_blob_zstd,
                                 text, sizeof(text), false);
        test_compress_decompress("ZSTD", compress_blob_zstd, decompress_blob_zstd,
                                 data, sizeof(data), true);

        test_decompress_startswith("ZSTD",
                                   compress_blob_zstd, decompress_startswith_zstd,
                                   text, sizeof(text), false);
        test_decompress_startswith("ZSTD",
                                   compress_blob_zstd, decompress_startswith_zstd,
                                   data, sizeof(data), true);
        test_decompress_startswith("ZSTD",
                                   compress_blob_zstd, decompress_startswith_zstd,
                                   huge, HUGE_SIZE, true);

        test_compress_stream("ZSTD", "zstdcat",
                             compress_stream_zstd, decompress_stream_zstd, srcfile);

        test_decompress_stream_sparse("ZSTD", compress_stream_zstd, decompress_stream_zstd);

        test_decompress_startswith_short("ZSTD", compress_blob_zstd, decompress_startswith_zstd);
#else
        log_info("/* ZSTD test skipped */");
#endif

        return 0;
#else
        return log_tests_skipped("no compression algorithm supported");
#endif
}
