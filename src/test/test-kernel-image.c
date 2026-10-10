/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "kernel-image.h"
#include "memfd-util.h"
#include "tests.h"
#include "unaligned.h"

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

TEST(gzip) {
        if (dlopen_zlib(LOG_DEBUG) < 0)
                return (void) log_tests_skipped("zlib not available");

        _cleanup_close_ int in = memfd_with(banner, strlen(banner));
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("test-kernel-image"));
        ASSERT_OK(compress_stream(COMPRESSION_GZIP, in, fd, UINT64_MAX, /* ret_uncompressed_size= */ NULL));

        assert_decompressed(fd);
}

static void test_zboot_one(Compression compression, const char *comp_type) {
        _cleanup_close_ int in = memfd_with(banner, strlen(banner)), payload_fd = ASSERT_OK(memfd_new("payload"));
        _cleanup_free_ char *payload = NULL;
        size_t payload_size;

        log_debug("/* %s(%s) */", __func__, comp_type);

        ASSERT_OK(compress_stream(compression, in, payload_fd, UINT64_MAX, /* ret_uncompressed_size= */ NULL));
        ASSERT_OK(read_full_file_full(payload_fd, /* filename= */ NULL, 0, SIZE_MAX, 0, NULL, &payload, &payload_size));

        /* The header of a ZBOOT image, see drivers/firmware/efi/libstub/zboot-header.S in the kernel */
        uint8_t header[0x40] = { 'M', 'Z', 0, 0, 'z', 'i', 'm', 'g' };
        unaligned_write_le32(header + 0x08, sizeof(header));
        unaligned_write_le32(header + 0x0c, payload_size);
        memcpy(header + 0x18, comp_type, strlen(comp_type));

        _cleanup_close_ int fd = memfd_with(header, sizeof(header));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, payload, payload_size, sizeof(header)), (ssize_t) payload_size);

        assert_decompressed(fd);
}

TEST(zboot) {
        if (dlopen_zlib(LOG_DEBUG) >= 0)
                test_zboot_one(COMPRESSION_GZIP, "gzip");

        if (dlopen_zstd(LOG_DEBUG) >= 0) {
                test_zboot_one(COMPRESSION_ZSTD, "zstd");
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
