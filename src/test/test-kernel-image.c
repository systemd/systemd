/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "kernel-image.h"
#include "memfd-util.h"
#include "tests.h"

static const char banner[] = "xx Linux version 6.1.0-test (builder@host) #1 SMP\n";

static int memfd_with(const void *data, size_t size) {
        int fd = ASSERT_OK(memfd_new("test-kernel-image"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, data, size, 0), (ssize_t) size);
        return fd;
}

static void assert_decompressed(int fd) {
        _cleanup_close_ int decompressed_fd = -EBADF;
        _cleanup_free_ char *data = NULL;
        size_t size;

        ASSERT_OK_POSITIVE(kernel_decompress(fd, &decompressed_fd));
        ASSERT_OK(read_full_file_full(decompressed_fd, /* filename= */ NULL, UINT64_MAX, SIZE_MAX, 0, NULL, &data, &size));
        ASSERT_EQ(size, strlen(banner));
        ASSERT_EQ(memcmp(data, banner, size), 0);
}

TEST(uncompressed) {
        _cleanup_close_ int fd = memfd_with(banner, strlen(banner)), decompressed_fd = -EBADF;

        ASSERT_OK_ZERO(kernel_decompress(fd, &decompressed_fd));
}

TEST(lzma) {
        /* The banner, compressed with Python's lzma.compress(..., format=lzma.FORMAT_ALONE). */
        static const uint8_t lzma[] = {
                0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x3c, 0x60,
                0x7c, 0x98, 0x69, 0x35, 0x65, 0x44, 0x67, 0x48, 0x11, 0x55, 0x22, 0x47, 0x03, 0xce, 0x64, 0x9c,
                0x59, 0xff, 0x9e, 0xf6, 0xf7, 0x06, 0x05, 0xfb, 0xe3, 0x5c, 0x55, 0x05, 0xb2, 0x16, 0x6f, 0x10,
                0xfa, 0xfd, 0xfb, 0x78, 0xa5, 0x4f, 0xfa, 0xda, 0xa5, 0x04, 0xbd, 0x32, 0x63, 0xee, 0x1e, 0xbd,
                0x89, 0xa2, 0x5b, 0x97, 0xff, 0xff, 0x80, 0x68, 0x80, 0x00,
        };

        if (dlopen_xz(LOG_DEBUG) < 0)
                return (void) log_tests_skipped("liblzma not available");

        _cleanup_close_ int fd = memfd_with(lzma, sizeof(lzma));
        assert_decompressed(fd);
}

TEST(gzip) {
        if (dlopen_zlib(LOG_DEBUG) < 0)
                return (void) log_tests_skipped("zlib not available");

        _cleanup_close_ int in = memfd_with(banner, strlen(banner));
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("test-kernel-image"));
        ASSERT_OK(compress_stream(COMPRESSION_GZIP, in, fd, UINT64_MAX, /* ret_uncompressed_size= */ NULL));

        assert_decompressed(fd);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
