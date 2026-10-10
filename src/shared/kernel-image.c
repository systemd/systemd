/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "env-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "kernel-image.h"
#include "log.h"
#include "memfd-util.h"
#include "pe-binary.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"

#define PE_SECTION_READ_MAX (16U*1024U)

static const char * const kernel_image_type_table[_KERNEL_IMAGE_TYPE_MAX] = {
        [KERNEL_IMAGE_TYPE_UNKNOWN] = "unknown",
        [KERNEL_IMAGE_TYPE_UKI]     = "uki",
        [KERNEL_IMAGE_TYPE_ADDON]   = "addon",
        [KERNEL_IMAGE_TYPE_PE]      = "pe",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(kernel_image_type, KernelImageType);

static int uki_read_pretty_name(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                char **ret) {

        _cleanup_free_ char *pname = NULL, *name = NULL;
        _cleanup_free_ void *osrel = NULL;
        size_t osrel_size;
        int r;

        assert(fd >= 0);
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);
        assert(ret);

        r = pe_read_section_data_by_name(
                        fd,
                        pe_header,
                        sections,
                        ".osrel",
                        /* max_size= */ PE_SECTION_READ_MAX,
                        &osrel,
                        &osrel_size);
        if (r == -ENXIO) { /* Section not found */
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read .osrel section: %m");

        r = parse_env_data(
                        osrel, osrel_size, ".osrel",
                        "PRETTY_NAME", &pname,
                        "NAME",        &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse embedded os-release file: %m");

        /* follow the same logic as os_release_pretty_name() */
        if (!isempty(pname))
                *ret = TAKE_PTR(pname);
        else if (!isempty(name))
                *ret = TAKE_PTR(name);
        else {
                char *n = strdup("Linux");
                if (!n)
                        return -ENOMEM;

                *ret = n;
        }

        return 0;
}

static int inspect_uki(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        int r;

        assert(fd >= 0);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (ret_cmdline) {
                r = pe_read_section_data_by_name(fd, pe_header, sections, ".cmdline", PE_SECTION_READ_MAX, (void**) &cmdline, NULL);
                if (r < 0 && r != -ENXIO) /* If the section doesn't exist, that's fine */
                        return r;
        }

        if (ret_uname) {
                r = pe_read_section_data_by_name(fd, pe_header, sections, ".uname", PE_SECTION_READ_MAX, (void**) &uname, NULL);
                if (r < 0 && r != -ENXIO) /* If the section doesn't exist, that's fine */
                        return r;
        }

        if (ret_pretty_name) {
                r = uki_read_pretty_name(fd, pe_header, sections, &pname);
                if (r < 0)
                        return r;
        }

        if (ret_cmdline)
                *ret_cmdline = TAKE_PTR(cmdline);
        if (ret_uname)
                *ret_uname = TAKE_PTR(uname);
        if (ret_pretty_name)
                *ret_pretty_name = TAKE_PTR(pname);

        return 0;
}

int inspect_kernel_full(
                int dir_fd,
                const char *filename,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        KernelImageType t = KERNEL_IMAGE_TYPE_UNKNOWN;
        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(wildcard_fd_is_valid(dir_fd));

        fd = xopenat(dir_fd, filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open kernel image file '%s': %m", strna(filename));

        r = pe_load_headers_and_sections(fd, &pe_header, &sections);
        if (r == -EBADMSG) /* not a valid PE file */
                goto not_uki;
        if (r < 0)
                return log_debug_errno(r, "Failed to parse kernel image file '%s': %m", strna(filename));

        if (pe_is_uki(pe_header, sections)) {
                r = inspect_uki(fd, pe_header, sections, ret_cmdline, ret_uname, ret_pretty_name);
                if (r < 0)
                        return r;

                t = KERNEL_IMAGE_TYPE_UKI;
                goto done;
        } else if (pe_is_addon(pe_header, sections)) {
                r = inspect_uki(fd, pe_header, sections, ret_cmdline, ret_uname, /* ret_pretty_name= */ NULL);
                if (r < 0)
                        return r;

                if (ret_pretty_name)
                        *ret_pretty_name = NULL;

                t = KERNEL_IMAGE_TYPE_ADDON;
                goto done;
        } else
                t = KERNEL_IMAGE_TYPE_PE;

not_uki:
        if (ret_cmdline)
                *ret_cmdline = NULL;
        if (ret_uname)
                *ret_uname = NULL;
        if (ret_pretty_name)
                *ret_pretty_name = NULL;

done:
        if (ret_type)
                *ret_type = t;

        return 0;
}

/* ZBOOT header layout — see linux/drivers/firmware/efi/libstub/zboot-header.S */
struct zboot_header {
        le16_t mz_magic;        /* 0x00: "MZ" DOS signature */
        le16_t _pad0;
        uint8_t zimg_magic[4];  /* 0x04: "zimg" identifier */
        le32_t payload_offset;  /* 0x08: offset to compressed payload */
        le32_t payload_size;    /* 0x0C: size of compressed payload */
        uint8_t _pad1[8];
        char comp_type[6];      /* 0x18: NUL-terminated compression type (e.g. "gzip", "zstd") */
        uint8_t _pad2[2];
} _packed_;
assert_cc(sizeof(struct zboot_header) == 0x20);
assert_cc(offsetof(struct zboot_header, comp_type) == 0x18);

static int decompress_to_memfd(Compression compression, int fd) {
        int r;

        _cleanup_close_ int memfd = memfd_new("kernel");
        if (memfd < 0)
                return log_debug_errno(memfd, "Failed to create memfd: %m");

        r = decompress_stream(compression, fd, memfd, /* max_bytes= */ UINT64_MAX);
        if (r < 0)
                return log_debug_errno(r, "Failed to decompress kernel: %m");

        if (lseek(memfd, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek memfd: %m");

        return TAKE_FD(memfd);
}

static int decompress_zboot_to_memfd(int fd, uint32_t payload_offset, uint32_t payload_size, const char *comp_type) {
        int r;

        Compression c = compression_from_string(comp_type);
        if (c < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Unsupported ZBOOT compression type '%s'.", comp_type);

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat ZBOOT image: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "Kernel image is not a regular file: %m");

        if (payload_offset < 0x20 ||
            payload_size == 0 ||
            payload_offset > (uint64_t) st.st_size ||
            payload_size > (uint64_t) st.st_size - payload_offset)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "ZBOOT payload offset/size invalid.");

        if (payload_size > 256 * U64_MB) /* generous for any compressed kernel */
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "ZBOOT payload unreasonably large.");

        _cleanup_free_ void *payload = malloc(payload_size);
        if (!payload)
                return log_oom_debug();

        ssize_t n = pread(fd, payload, payload_size, payload_offset);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read ZBOOT payload: %m");
        if ((uint32_t) n < payload_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read of ZBOOT payload.");

        _cleanup_free_ void *decompressed = NULL;
        size_t decompressed_size;
        /* Cap the decompressed size as well: a zstd frame that doesn't record its content size is
         * decompressed by growing the output buffer as we go, so without a limit a malicious image could
         * expand far beyond its (already bounded) compressed size. 1 GiB is generous for any real kernel. */
        r = decompress_blob(c, payload, payload_size, &decompressed, &decompressed_size,
                            /* dst_max= */ U64_GB);
        if (r < 0)
                return log_debug_errno(r, "Failed to decompress ZBOOT payload: %m");

        payload = mfree(payload);

        _cleanup_close_ int memfd = memfd_new("kernel");
        if (memfd < 0)
                return log_debug_errno(memfd, "Failed to create memfd: %m");

        r = loop_write(memfd, decompressed, decompressed_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to write decompressed kernel to memfd: %m");

        if (lseek(memfd, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek memfd: %m");

        return TAKE_FD(memfd);
}

int kernel_decompress(int fd, int *ret_fd) {
        uint8_t magic[CONST_MAX(8U, COMPRESSION_MAGIC_BYTES_MAX)];
        ssize_t n;

        assert(fd >= 0);
        assert(ret_fd);

        n = pread(fd, magic, sizeof(magic), /* offset= */ 0);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read kernel magic: %m");
        if ((size_t) n < sizeof(magic)) {
                *ret_fd = -EBADF;
                return 0;
        }

        if (magic[0] == 'M' && magic[1] == 'Z') {
                if (memcmp(magic + 4, "zimg", 4) != 0) {
                        *ret_fd = -EBADF;
                        return 0;
                }

                struct zboot_header h;

                n = pread(fd, &h, sizeof(h), /* offset= */ 0);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read ZBOOT header: %m");
                if ((size_t) n < sizeof(h))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read of ZBOOT header.");

                char comp_type[sizeof(h.comp_type) + 1];
                *(char*) mempcpy(comp_type, h.comp_type, sizeof(h.comp_type)) = 0;

                uint32_t payload_offset = le32toh(h.payload_offset),
                         payload_size = le32toh(h.payload_size);

                log_debug("Detected ZBOOT image (compression=%s, offset=%"PRIu32", size=%"PRIu32")",
                          comp_type, payload_offset, payload_size);

                int decompressed_fd = decompress_zboot_to_memfd(fd, payload_offset, payload_size, comp_type);
                if (decompressed_fd < 0)
                        return decompressed_fd;

                *ret_fd = decompressed_fd;
                return 1;
        }

        Compression c = compression_detect_from_magic(magic);
        if (c < 0) {
                *ret_fd = -EBADF;
                return 0;
        }

        log_debug("Detected %s-compressed kernel, decompressing.", compression_to_string(c));

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek kernel fd: %m");

        int decompressed_fd = decompress_to_memfd(c, fd);
        if (decompressed_fd < 0)
                return decompressed_fd;

        *ret_fd = decompressed_fd;
        return 1;
}
