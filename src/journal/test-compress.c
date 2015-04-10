/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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
#include "random-util.h"

#ifdef HAVE_XZ
# define XZ_OK 0
#else
# define XZ_OK -EPROTONOSUPPORT
#endif

#ifdef HAVE_LZ4
# define LZ4_OK 0
#else
# define LZ4_OK -EPROTONOSUPPORT
#endif

typedef int (compress_blob_t)(const void *src, uint64_t src_size,
                              void *dst, size_t *dst_size);
typedef int (decompress_blob_t)(const void *src, uint64_t src_size,
                                void **dst, size_t *dst_alloc_size,
                                size_t* dst_size, size_t dst_max);
typedef int (decompress_sw_t)(const void *src, uint64_t src_size,
                              void **buffer, size_t *buffer_size,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra);

typedef int (compress_stream_t)(int fdf, int fdt, off_t max_bytes);
typedef int (decompress_stream_t)(int fdf, int fdt, off_t max_size);

static void test_compress_decompress(int compression,
                                     compress_blob_t compress,
                                     decompress_blob_t decompress,
                                     const char *data,
                                     size_t data_len,
                                     bool may_fail) {
        char compressed[512];
        size_t csize = 512;
        size_t usize = 0;
        _cleanup_free_ char *decompressed = NULL;
        int r;

        log_info("/* testing %s %s blob compression/decompression */",
                 object_compressed_to_string(compression), data);

        r = compress(data, data_len, compressed, &csize);
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

        char compressed[512];
        size_t csize = 512;
        size_t usize = 0;
        _cleanup_free_ char *decompressed = NULL;
        int r;

        log_info("/* testing decompress_startswith with %s on %s text*/",
                 object_compressed_to_string(compression), data);

        r = compress(data, data_len, compressed, &csize);
        if (r == -ENOBUFS) {
                log_info_errno(r, "compression failed: %m");
                assert_se(may_fail);
                return;
        }
        assert_se(r == 0);

        assert_se(decompress_sw(compressed,
                                csize,
                                (void **) &decompressed,
                                &usize,
                                data, strlen(data), '\0') > 0);
        assert_se(decompress_sw(compressed,
                                csize,
                                (void **) &decompressed,
                                &usize,
                                data, strlen(data), 'w') == 0);
        assert_se(decompress_sw(compressed,
                                csize,
                                (void **) &decompressed,
                                &usize,
                                "barbarbar", 9, ' ') == 0);
        assert_se(decompress_sw(compressed,
                                csize,
                                (void **) &decompressed,
                                &usize,
                                data, strlen(data), '\0') > 0);
}

static void test_compress_stream(int compression,
                                 const char* cat,
                                 compress_stream_t compress,
                                 decompress_stream_t decompress,
                                 const char *srcfile) {

        _cleanup_close_ int src = -1, dst = -1, dst2 = -1;
        char pattern[] = "/tmp/systemd-test.xz.XXXXXX",
             pattern2[] = "/tmp/systemd-test.xz.XXXXXX";
        int r;
        _cleanup_free_ char *cmd = NULL, *cmd2;
        struct stat st = {};

        log_debug("/* testing %s compression */",
                  object_compressed_to_string(compression));

        log_debug("/* create source from %s */", srcfile);

        assert_se((src = open(srcfile, O_RDONLY|O_CLOEXEC)) >= 0);

        log_debug("/* test compression */");

        assert_se((dst = mkostemp_safe(pattern, O_RDWR|O_CLOEXEC)) >= 0);

        assert_se(compress(src, dst, -1) == 0);

        if (cat) {
                assert_se(asprintf(&cmd, "%s %s | diff %s -", cat, pattern, srcfile) > 0);
                assert_se(system(cmd) == 0);
        }

        log_debug("/* test decompression */");

        assert_se((dst2 = mkostemp_safe(pattern2, O_RDWR|O_CLOEXEC)) >= 0);

        assert_se(stat(srcfile, &st) == 0);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        r = decompress(dst, dst2, st.st_size);
        assert_se(r == 0);

        assert_se(asprintf(&cmd2, "diff %s %s", srcfile, pattern2) > 0);
        assert_se(system(cmd2) == 0);

        log_debug("/* test faulty decompression */");

        assert_se(lseek(dst, 1, SEEK_SET) == 1);
        r = decompress(dst, dst2, st.st_size);
        assert_se(r == -EBADMSG);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        assert_se(lseek(dst2, 0, SEEK_SET) == 0);
        r = decompress(dst, dst2, st.st_size - 1);
        assert_se(r == -EFBIG);

        assert_se(unlink(pattern) == 0);
        assert_se(unlink(pattern2) == 0);
}

int main(int argc, char *argv[]) {
        const char text[] =
                "text\0foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
                "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";

        char data[512] = "random\0";

        log_set_max_level(LOG_DEBUG);

        random_bytes(data + 7, sizeof(data) - 7);

#ifdef HAVE_XZ
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
        test_compress_stream(OBJECT_COMPRESSED_XZ, "xzcat",
                             compress_stream_xz, decompress_stream_xz, argv[0]);
#else
        log_info("/* XZ test skipped */");
#endif

#ifdef HAVE_LZ4
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

        /* Produced stream is not compatible with lz4 binary, skip lz4cat check. */
        test_compress_stream(OBJECT_COMPRESSED_LZ4, NULL,
                             compress_stream_lz4, decompress_stream_lz4, argv[0]);
#else
        log_info("/* LZ4 test skipped */");
#endif

        return 0;
}
