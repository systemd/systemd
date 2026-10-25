/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "env-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "kernel-image.h"
#include "log.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "pe-binary.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unaligned.h"
#include "utf8.h"

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

int inspect_kernel_fd(
                int fd,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        KernelImageType t = KERNEL_IMAGE_TYPE_UNKNOWN;
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        assert(fd >= 0);

        r = pe_load_headers_and_sections(fd, &pe_header, &sections);
        if (r == -EBADMSG) /* not a valid PE file */
                goto not_uki;
        if (r < 0)
                return log_debug_errno(r, "Failed to parse kernel image file: %m");

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

int inspect_kernel_full(
                int dir_fd,
                const char *filename,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_close_ int fd = -EBADF;

        assert(wildcard_fd_is_valid(dir_fd));

        fd = xopenat(dir_fd, filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open kernel image file '%s': %m", strna(filename));

        return inspect_kernel_fd(fd, ret_type, ret_cmdline, ret_uname, ret_pretty_name);
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

static int decompress_to_memfd(Compression compression, DecompressFlags flags, int fd, uint64_t max_bytes) {
        int r;

        _cleanup_close_ int memfd = memfd_new("kernel");
        if (memfd < 0)
                return log_debug_errno(memfd, "Failed to create memfd: %m");

        r = decompress_stream_full(compression, fd, memfd, max_bytes, flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to decompress kernel: %m");

        if (lseek(memfd, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek memfd: %m");

        return TAKE_FD(memfd);
}

static Compression zboot_compression_from_string(const char *s, DecompressFlags *ret_flags) {
        DecompressFlags flags = 0;
        Compression c;

        assert(ret_flags);

        /* The kernel compresses "lzma" payloads in the legacy .lzma format and "xzkern" payloads in the .xz
         * format. Kernels before 6.13 write "zstd22" for zstd payloads. */
        if (streq(s, "lzma")) {
                c = COMPRESSION_XZ;
                flags = DECOMPRESS_LEGACY_LZMA;
        } else if (streq(s, "xzkern"))
                c = COMPRESSION_XZ;
        else if (streq(s, "zstd22"))
                c = COMPRESSION_ZSTD;
        else {
                c = compression_from_string(s);
                if (c < 0)
                        return c;
        }

        *ret_flags = flags;
        return c;
}

static int decompress_zboot_to_memfd(int fd, uint32_t payload_offset, uint32_t payload_size, const char *comp_type) {
        DecompressFlags flags;
        int r;

        Compression c = zboot_compression_from_string(comp_type, &flags);
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

        _cleanup_close_ int payload_fd = memfd_new_and_seal("zboot-payload", payload, payload_size);
        if (payload_fd < 0)
                return log_debug_errno(payload_fd, "Failed to create memfd: %m");

        payload = mfree(payload);

        /* The compressed size is limited above. Without a limit on the decompressed size, a malicious image
         * could still expand to an arbitrary size. 1 GiB is enough for any real kernel. */
        return decompress_to_memfd(c, flags, payload_fd, /* max_bytes= */ U64_GB);
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

        DecompressFlags flags = 0;
        Compression c = compression_detect_from_magic(magic);
        /* The legacy .lzma format has no magic. Its header usually starts with the bytes 5d 00 00, which
         * compression_detect_from_magic() does not check for. */
        if (c < 0 && memcmp(magic, (const uint8_t[]) { 0x5d, 0x00, 0x00 }, 3) == 0) {
                c = COMPRESSION_XZ;
                flags = DECOMPRESS_LEGACY_LZMA;
        }
        if (c < 0) {
                *ret_fd = -EBADF;
                return 0;
        }

        log_debug("Detected %s-compressed kernel, decompressing.", compression_to_string(c));

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek kernel fd: %m");

        int decompressed_fd = decompress_to_memfd(c, flags, fd, /* max_bytes= */ UINT64_MAX);
        if (decompressed_fd < 0)
                return decompressed_fd;

        *ret_fd = decompressed_fd;
        return 1;
}

static int uname_from_x86_boot_header(int fd, char **ret) {
        uint8_t header[0x210];
        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        /* See the description of the real-mode kernel header in the kernel's
         * Documentation/arch/x86/boot.rst. */

        n = pread(fd, header, sizeof(header), 0);
        if (n < 0)
                return -errno;
        if ((size_t) n < sizeof(header) || memcmp(header + 0x202, "HdrS", 4) != 0)
                return 0;

        char text[129] = {};
        n = pread(fd, text, sizeof(text) - 1, 0x200 + unaligned_read_le16(header + 0x20e));
        if (n < 0)
                return -errno;

        /* The string has the form "VERSION (USER@HOST) #BUILD ...". */
        size_t l = strspn(text, LOWERCASE_LETTERS DIGITS "._+-");
        if (l == 0 || !startswith(text + l, " ("))
                return 0;

        const char *p = text + l + 2;
        p += strcspn(p, " )");
        if (!startswith(p, ") #"))
                return 0;

        char *s = strndup(text, l);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 1;
}

static int uname_from_elf_note(const uint8_t *data, size_t size, char **ret) {
        assert(data || size == 0);
        assert(ret);

        /* The kernel stores its version in a note with the name "Linux" and the type
         * LINUX_ELFNOTE_BUILD_SALT. */

        if (size < EI_NIDENT || memcmp(data, ELFMAG, SELFMAG) != 0)
                return 0;

        bool is_64 = data[EI_CLASS] == ELFCLASS64, le = data[EI_DATA] == ELFDATA2LSB;
        if (!IN_SET(data[EI_CLASS], ELFCLASS32, ELFCLASS64) || !IN_SET(data[EI_DATA], ELFDATA2LSB, ELFDATA2MSB))
                return 0;

#define READ16(p) (le ? unaligned_read_le16(p) : unaligned_read_be16(p))
#define READ32(p) (le ? unaligned_read_le32(p) : unaligned_read_be32(p))
#define READ64(p) (le ? unaligned_read_le64(p) : unaligned_read_be64(p))

        size_t ehdr_size = is_64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
        if (size < ehdr_size)
                return 0;

        uint64_t phoff = is_64 ? READ64(data + offsetof(Elf64_Ehdr, e_phoff)) : READ32(data + offsetof(Elf32_Ehdr, e_phoff));
        uint16_t phentsize = READ16(data + (is_64 ? offsetof(Elf64_Ehdr, e_phentsize) : offsetof(Elf32_Ehdr, e_phentsize))),
                 phnum = READ16(data + (is_64 ? offsetof(Elf64_Ehdr, e_phnum) : offsetof(Elf32_Ehdr, e_phnum)));

        if (phentsize < (is_64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr)))
                return 0;

        for (uint16_t i = 0; i < phnum; i++) {
                uint64_t ph = phoff + (uint64_t) i * phentsize;
                if (ph > size || size - ph < phentsize)
                        return 0;

                const uint8_t *p = data + ph;
                uint32_t type = READ32(p + (is_64 ? offsetof(Elf64_Phdr, p_type) : offsetof(Elf32_Phdr, p_type)));
                if (type != PT_NOTE)
                        continue;

                uint64_t offset = is_64 ? READ64(p + offsetof(Elf64_Phdr, p_offset)) : READ32(p + offsetof(Elf32_Phdr, p_offset)),
                         filesz = is_64 ? READ64(p + offsetof(Elf64_Phdr, p_filesz)) : READ32(p + offsetof(Elf32_Phdr, p_filesz));
                if (offset > size || filesz > size - offset)
                        continue;

                for (uint64_t q = offset; q + 12 <= offset + filesz;) {
                        uint32_t namesz = READ32(data + q), descsz = READ32(data + q + 4), ntype = READ32(data + q + 8);
                        uint64_t name = q + 12, desc = name + ALIGN_TO_U64(namesz, 4), next = desc + ALIGN_TO_U64(descsz, 4);
                        if (next > offset + filesz)
                                break;

                        if (ntype == 0x100 && namesz == 6 && memcmp(data + name, "Linux", 6) == 0) {
                                char *s = strndup((const char*) data + desc, descsz);
                                if (!s)
                                        return -ENOMEM;

                                *ret = s;
                                return 1;
                        }

                        q = next;
                }
        }

#undef READ16
#undef READ32
#undef READ64

        return 0;
}

static int uname_from_banner(const uint8_t *data, size_t size, char **ret) {
        static const char banner[] = "Linux version ";

        assert(data || size == 0);
        assert(ret);

        /* The banner has the form "Linux version VERSION (USER@HOST) ...". */

        for (const uint8_t *p = data; p < data + size;) {
                p = memmem_safe(p, data + size - p, banner, strlen(banner));
                if (!p)
                        return 0;

                p += strlen(banner);

                size_t l = 0;
                while (p + l < data + size && !strchr(WHITESPACE, p[l]) && p[l] != 0)
                        l++;

                if (l >= 2 && ascii_isdigit(p[0]) && p[1] == '.' &&
                    p + l + 2 <= data + size && p[l] == ' ' && p[l + 1] == '(') {
                        char *s = strndup((const char*) p, l);
                        if (!s)
                                return -ENOMEM;

                        *ret = s;
                        return 1;
                }
        }

        return 0;
}

static int uname_from_image_data(int fd, char **ret) {
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return -errno;

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        if (st.st_size == 0)
                return 0;

        void *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        r = uname_from_elf_note(p, st.st_size, ret);
        if (r == 0)
                r = uname_from_banner(p, st.st_size, ret);

        (void) munmap(p, st.st_size);
        return r;
}

int kernel_find_uname(int fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(fd >= 0);
        assert(ret);

        r = uname_from_x86_boot_header(fd, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to read x86 boot header: %m");
        if (r == 0) {
                _cleanup_close_ int decompressed_fd = -EBADF;

                r = kernel_decompress(fd, &decompressed_fd);
                if (r < 0)
                        return r;

                r = uname_from_image_data(r > 0 ? decompressed_fd : fd, &s);
                if (r < 0)
                        return log_debug_errno(r, "Failed to search kernel image for its version: %m");
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image does not contain its version.");
        }

        if (!utf8_is_valid(s))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Kernel version is not valid UTF-8.");

        *ret = TAKE_PTR(s);
        return 0;
}
