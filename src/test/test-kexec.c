/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "io-util.h"
#include "reboot-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"

static int find_kernel_image(char **ret) {
        struct utsname u;

        ASSERT_OK_ERRNO(uname(&u));

        /* Kernel image names vary across architectures and distributions:
         *   vmlinuz     — compressed Linux kernel (x86, most distros)
         *   vmlinux     — uncompressed ELF kernel (ppc64, s390)
         *   Image       — uncompressed flat binary (arm64, riscv)
         *   Image.gz    — gzip-compressed Image (arm64)
         *   zImage      — compressed kernel (arm 32-bit)
         *   vmlinuz.efi — EFI ZBOOT PE wrapper (arm64 with CONFIG_EFI_ZBOOT) */
        static const char *const names[] = {
                "vmlinuz",
                "vmlinux",
                "Image",
                "Image.gz",
                "zImage",
                "vmlinuz.efi",
        };

        /* Try /usr/lib/modules/<version>/<name> first (kernel-install convention),
         * then /boot/<name>-<version>, then /boot/<name> */
        for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                _cleanup_free_ char *path = NULL;

                path = strjoin("/usr/lib/modules/", u.release, "/", names[i]);
                if (!path)
                        return -ENOMEM;

                if (access(path, R_OK) >= 0) {
                        *ret = TAKE_PTR(path);
                        return 0;
                }
        }

        /* /boot may not be accessible without root, skip gracefully */
        if (access("/boot", R_OK) >= 0) {
                for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                        _cleanup_free_ char *path = NULL;

                        path = strjoin("/boot/", names[i], "-", u.release);
                        if (!path)
                                return -ENOMEM;

                        if (access(path, R_OK) >= 0) {
                                *ret = TAKE_PTR(path);
                                return 0;
                        }
                }

                for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                        _cleanup_free_ char *path = NULL;

                        path = strjoin("/boot/", names[i]);
                        if (!path)
                                return -ENOMEM;

                        if (access(path, R_OK) >= 0) {
                                *ret = TAKE_PTR(path);
                                return 0;
                        }
                }
        }

        return -ENOENT;
}

TEST(passthrough_unrecognized) {
        /* A file with unrecognized magic should pass through as-is (return 0) */
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/test-kexec.XXXXXX";

        ASSERT_OK(fd = mkostemp_safe(path));
        ASSERT_OK_EQ_ERRNO(write(fd, "HELLO WORLD\0", 12), 12);
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));

        _cleanup_close_ int kernel_fd = -EBADF, initrd_fd = -EBADF;
        ASSERT_OK_ZERO(kexec_maybe_decompress_kernel(path, fd, &kernel_fd, &initrd_fd));
        ASSERT_EQ(kernel_fd, -EBADF);
        ASSERT_EQ(initrd_fd, -EBADF);
}

TEST(gzip_round_trip) {
        _cleanup_close_ int src_fd = -EBADF, gz_fd = -EBADF;
        _cleanup_(unlink_tempfilep) char
                src_path[] = "/tmp/test-kexec-src.XXXXXX",
                gz_path[] = "/tmp/test-kexec-gz.XXXXXX";
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0) {
                log_tests_skipped("zlib not available");
                return;
        }

        /* Create a source file with known content */
        ASSERT_OK(src_fd = mkostemp_safe(src_path));
        char buf[4096];
        memset(buf, 'A', sizeof(buf));
        ASSERT_OK(loop_write(src_fd, buf, sizeof(buf)));

        /* Compress it with gzip */
        ASSERT_OK_ERRNO(lseek(src_fd, 0, SEEK_SET));
        ASSERT_OK(gz_fd = mkostemp_safe(gz_path));
        ASSERT_OK(compress_stream(COMPRESSION_GZIP, src_fd, gz_fd, UINT64_MAX, NULL));

        /* Feed the gzip file to kexec_maybe_decompress_kernel */
        ASSERT_OK_ERRNO(lseek(gz_fd, 0, SEEK_SET));

        _cleanup_close_ int kernel_fd = -EBADF, initrd_fd = -EBADF;
        ASSERT_OK_POSITIVE(kexec_maybe_decompress_kernel(gz_path, gz_fd, &kernel_fd, &initrd_fd));
        ASSERT_GE(kernel_fd, 0);
        ASSERT_EQ(initrd_fd, -EBADF);

        /* Verify the decompressed content matches the original */
        char result[4096];
        ASSERT_OK_EQ_ERRNO(pread(kernel_fd, result, sizeof(result), 0), (ssize_t) sizeof(result));
        ASSERT_EQ(memcmp(buf, result, sizeof(buf)), 0);
}

TEST(zboot_synthetic) {
        /* Construct a minimal ZBOOT header with a gzip-compressed payload */
        _cleanup_close_ int src_fd = -EBADF, gz_fd = -EBADF, zboot_fd = -EBADF;
        _cleanup_(unlink_tempfilep) char
                src_path[] = "/tmp/test-kexec-zboot-src.XXXXXX",
                gz_path[] = "/tmp/test-kexec-zboot-gz.XXXXXX",
                zboot_path[] = "/tmp/test-kexec-zboot.XXXXXX";
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0) {
                log_tests_skipped("zlib not available");
                return;
        }

        /* Create and compress a payload */
        char payload[512];
        memset(payload, 'K', sizeof(payload));

        ASSERT_OK(src_fd = mkostemp_safe(src_path));
        ASSERT_OK(loop_write(src_fd, payload, sizeof(payload)));
        ASSERT_OK_ERRNO(lseek(src_fd, 0, SEEK_SET));

        ASSERT_OK(gz_fd = mkostemp_safe(gz_path));
        ASSERT_OK(compress_stream(COMPRESSION_GZIP, src_fd, gz_fd, UINT64_MAX, NULL));

        /* Read the compressed data */
        struct stat st;
        ASSERT_OK_ERRNO(fstat(gz_fd, &st));
        size_t compressed_size = st.st_size;
        _cleanup_free_ void *compressed = malloc(compressed_size);
        ASSERT_NOT_NULL(compressed);
        ASSERT_OK_EQ_ERRNO(pread(gz_fd, compressed, compressed_size, 0), (ssize_t) compressed_size);

        /* Build the ZBOOT header:
         *   0x00: "MZ"
         *   0x04: "zimg"
         *   0x08: payload offset (LE32)
         *   0x0C: payload size (LE32)
         *   0x18: "gzip\0" */
        uint8_t header[0x40] = {};
        uint32_t payload_offset = sizeof(header);

        header[0] = 'M';
        header[1] = 'Z';
        memcpy(header + 0x04, "zimg", 4);
        unaligned_write_le32(header + 0x08, payload_offset);
        unaligned_write_le32(header + 0x0C, (uint32_t) compressed_size);
        memcpy(header + 0x18, "gzip", 5);

        ASSERT_OK(zboot_fd = mkostemp_safe(zboot_path));
        ASSERT_OK(loop_write(zboot_fd, header, sizeof(header)));
        ASSERT_OK(loop_write(zboot_fd, compressed, compressed_size));
        ASSERT_OK_ERRNO(lseek(zboot_fd, 0, SEEK_SET));

        /* Test extraction */
        _cleanup_close_ int kernel_fd = -EBADF, initrd_fd = -EBADF;
        ASSERT_OK_POSITIVE(kexec_maybe_decompress_kernel(zboot_path, zboot_fd, &kernel_fd, &initrd_fd));
        ASSERT_GE(kernel_fd, 0);

        /* Verify decompressed content matches original payload */
        char result[512];
        ASSERT_OK_EQ_ERRNO(pread(kernel_fd, result, sizeof(result), 0), (ssize_t) sizeof(result));
        ASSERT_EQ(memcmp(payload, result, sizeof(payload)), 0);
}

TEST(system_kernel) {
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = find_kernel_image(&path);
        if (r < 0) {
                log_tests_skipped_errno(r, "No kernel image found on this system");
                return;
        }

        log_info("Found kernel image: %s", path);

        fd = open(path, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                log_tests_skipped_errno(errno, "Cannot open kernel image '%s'", path);
                return;
        }

        _cleanup_close_ int kernel_fd = -EBADF, initrd_fd = -EBADF;
        ASSERT_OK(r = kexec_maybe_decompress_kernel(path, fd, &kernel_fd, &initrd_fd));

        if (r == 0) {
                log_info("Kernel image was not compressed (passed through as-is).");
                return;
        }

        log_info("Kernel image was decompressed/extracted successfully.");
        ASSERT_GE(kernel_fd, 0);

        /* Verify the decompressed result is non-empty and looks plausible */
        struct stat st;
        ASSERT_OK_ERRNO(fstat(kernel_fd, &st));
        ASSERT_GT(st.st_size, 0);
        log_info("Decompressed kernel size: %zu bytes", (size_t) st.st_size);

        /* Read the first bytes and check for known kernel magic */
        uint8_t magic[8];
        ASSERT_OK_EQ_ERRNO(pread(kernel_fd, magic, sizeof(magic), 0), (ssize_t) sizeof(magic));

        if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
                log_info("Decompressed kernel is an ELF image.");
        else if (magic[0] == 'M' && magic[1] == 'Z')
                log_info("Decompressed kernel is a PE image.");
        else
                log_info("Decompressed kernel magic: %02x %02x %02x %02x %02x %02x %02x %02x",
                         magic[0], magic[1], magic[2], magic[3],
                         magic[4], magic[5], magic[6], magic[7]);

        /* If a UKI initrd was extracted, verify it too */
        if (initrd_fd >= 0) {
                ASSERT_OK_ERRNO(fstat(initrd_fd, &st));
                ASSERT_GT(st.st_size, 0);
                log_info("Extracted initrd size: %zu bytes", (size_t) st.st_size);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
