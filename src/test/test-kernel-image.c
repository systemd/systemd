/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "kernel-image.h"
#include "memfd-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
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

static void assert_uname(int fd, const char *expected) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(kernel_find_uname(fd, &s));
        ASSERT_STREQ(s, expected);
}

static void assert_no_uname(int (*func)(int fd, char **ret), int fd) {
        _cleanup_free_ char *s = NULL;

        ASSERT_ERROR(func(fd, &s), ENODATA);
        ASSERT_NULL(s);
}

TEST(uncompressed) {
        _cleanup_close_ int fd = memfd_with(banner, strlen(banner)), decompressed_fd = -EBADF;

        ASSERT_OK_ZERO(kernel_decompress(fd, &decompressed_fd));
        assert_uname(fd, "6.1.0-test");
        assert_no_uname(kernel_uname_from_x86_boot_header, fd);
        assert_no_uname(kernel_uname_from_elf_note, fd);
}

TEST(not_found) {
        _cleanup_free_ char *data = NULL;

        ASSERT_NOT_NULL(data = strjoin("Linux version x.y (no digit) and Linux version 6.1 without parenthesis "
                                       "and Linux version 6.1/x (invalid) and Linux version abc.1 (no digit) "
                                       "and Linux version 6.", strrepa("a", 80), " (too long)"));

        _cleanup_close_ int fd = memfd_with(data, strlen(data));
        assert_no_uname(kernel_find_uname, fd);
        assert_no_uname(kernel_uname_from_banner, fd);
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
        assert_uname(fd, "6.1.0-test");
}

TEST(gzip) {
        if (dlopen_zlib(LOG_DEBUG) < 0)
                return (void) log_tests_skipped("zlib not available");

        _cleanup_close_ int in = memfd_with(banner, strlen(banner));
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("test-kernel-image"));
        ASSERT_OK(compress_stream(COMPRESSION_GZIP, in, fd, UINT64_MAX, /* ret_uncompressed_size= */ NULL));

        assert_decompressed(fd);
        assert_uname(fd, "6.1.0-test");
}

TEST(banner_two_digit_major) {
        static const char data[] = "Linux version 10.0.0-test (builder@host) #1 SMP\n";
        _cleanup_close_ int fd = memfd_with(data, strlen(data));
        assert_uname(fd, "10.0.0-test");
}

TEST(x86_boot_header) {
        uint8_t data[0x400] = {};
        static const char version[] = "6.2.0-1-X86 (builder@host) #1 SMP";

        memcpy(data + 0x202, "HdrS", 4);
        unaligned_write_le16(data + 0x20e, 0x100);
        memcpy(data + 0x300, version, strlen(version));

        _cleanup_close_ int fd = memfd_with(data, sizeof(data));
        assert_uname(fd, "6.2.0-1-X86");
        assert_no_uname(kernel_uname_from_banner, fd);
}

static int elf_note_with(const char *desc, size_t descsz, const char *trailer) {
        struct {
                Elf64_Ehdr ehdr;
                Elf64_Phdr phdr;
                Elf64_Nhdr nhdr;
                char name[8];
                char desc[72];
        } _packed_ elf = {
                .ehdr = {
                        .e_ident = {
                                ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64,
                                __BYTE_ORDER == __LITTLE_ENDIAN ? ELFDATA2LSB : ELFDATA2MSB,
                                EV_CURRENT,
                        },
                        .e_phoff = offsetof(typeof(elf), phdr),
                        .e_phentsize = sizeof(Elf64_Phdr),
                        .e_phnum = 1,
                },
                .phdr = {
                        .p_type = PT_NOTE,
                        .p_offset = offsetof(typeof(elf), nhdr),
                        .p_filesz = sizeof(Elf64_Nhdr) + 8 + 72,
                },
                .nhdr = {
                        .n_namesz = 6,
                        .n_descsz = descsz,
                        .n_type = 0x100,
                },
                .name = "Linux",
        };

        ASSERT_LE(descsz, sizeof(elf.desc));
        memcpy(elf.desc, desc, descsz);

        int fd = memfd_with(&elf, sizeof(elf));
        if (trailer)
                ASSERT_OK_EQ_ERRNO(pwrite(fd, trailer, strlen(trailer), sizeof(elf)), (ssize_t) strlen(trailer));

        return fd;
}

TEST(elf_note) {
        _cleanup_close_ int fd = elf_note_with("6.3.0-elf", 10, /* trailer= */ NULL);
        assert_uname(fd, "6.3.0-elf");
        assert_no_uname(kernel_uname_from_banner, fd);
}

static void test_elf_note_ignored_one(const char *desc, size_t descsz) {
        _cleanup_close_ int fd = elf_note_with(desc, descsz, banner);

        assert_no_uname(kernel_uname_from_elf_note, fd);
        assert_uname(fd, "6.1.0-test");
}

TEST(elf_note_ignored) {
        _cleanup_free_ char *too_long = NULL;

        /* The upstream default of CONFIG_BUILD_SALT is an empty string. */
        test_elf_note_ignored_one("", 1);
        test_elf_note_ignored_one("abc123", 7);
        test_elf_note_ignored_one("not valid", 10);
        test_elf_note_ignored_one("6.3\0x", 6);

        ASSERT_NOT_NULL(too_long = strjoin("6.", strrepa("a", 68)));
        test_elf_note_ignored_one(too_long, strlen(too_long) + 1);
}

static bool check_uname_source(const char *path, const char *source, int r, const char *s, const char *expected) {
        if (r == -ENODATA) {
                log_info("%s: %s does not contain the kernel version.", path, source);
                return false;
        }

        ASSERT_OK(r);
        log_info("%s: %s contains kernel version %s.", path, source, s);
        ASSERT_STREQ(s, expected);
        return true;
}

TEST(installed_kernels) {
        _cleanup_strv_free_ char **paths = NULL;

        /* The directory name of an installed kernel is its version. */
        int r = glob_extend(&paths, "/usr/lib/modules/*/vmlinuz", /* flags= */ 0);
        if (r == -ENOENT)
                return (void) log_tests_skipped("No installed kernels found");
        ASSERT_OK(r);

        STRV_FOREACH(path, paths) {
                _cleanup_free_ char *dir = NULL, *version = NULL;
                ASSERT_OK(path_extract_directory(*path, &dir));
                ASSERT_OK(path_extract_filename(dir, &version));

                _cleanup_close_ int fd = open(*path, O_RDONLY|O_CLOEXEC);
                if (fd < 0 && ERRNO_IS_PRIVILEGE(errno)) {
                        log_notice_errno(errno, "Cannot open %s, skipping: %m", *path);
                        continue;
                }
                ASSERT_OK_ERRNO(fd);

                _cleanup_close_ int decompressed_fd = -EBADF;
                r = kernel_decompress(fd, &decompressed_fd);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                        log_notice_errno(r, "Cannot decompress %s, skipping: %m", *path);
                        continue;
                }
                ASSERT_OK(r);
                int data_fd = r > 0 ? decompressed_fd : fd;

                _cleanup_free_ char *from_header = NULL, *from_note = NULL, *from_banner = NULL;
                bool found = false;

                r = kernel_uname_from_x86_boot_header(fd, &from_header);
                found = check_uname_source(*path, "x86 boot header", r, from_header, version) || found;

                r = kernel_uname_from_elf_note(data_fd, &from_note);
                found = check_uname_source(*path, "ELF note", r, from_note, version) || found;

                r = kernel_uname_from_banner(data_fd, &from_banner);
                found = check_uname_source(*path, "kernel banner", r, from_banner, version) || found;

                _cleanup_free_ char *s = NULL;
                r = kernel_find_uname(fd, &s);
                if (!found) {
                        /* s390x kernels contain their version in an s390 specific header.
                         * kernel_find_uname() doesn't parse that header. */
                        ASSERT_ERROR(r, ENODATA);
                        continue;
                }
                ASSERT_OK(r);
                ASSERT_STREQ(s, version);
        }
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
        assert_uname(fd, "6.1.0-test");
}

TEST(zboot) {
        if (dlopen_zlib(LOG_DEBUG) >= 0)
                test_zboot_one(COMPRESSION_GZIP, "gzip");

        if (dlopen_zstd(LOG_DEBUG) >= 0) {
                test_zboot_one(COMPRESSION_ZSTD, "zstd");
                test_zboot_one(COMPRESSION_ZSTD, "zstd22");
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
