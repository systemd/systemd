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
#include "linux-x86.h"
#include "log.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "pe-binary.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unaligned.h"

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

        int decompressed_fd = decompress_to_memfd(c, flags, fd, /* max_bytes= */ U64_GB);
        if (decompressed_fd < 0)
                return decompressed_fd;

        *ret_fd = decompressed_fd;
        return 1;
}

/* The kernel_version field of the x86 boot header contains the offset of the version string minus 0x200. */
#define X86_KERNEL_VERSION_OFFSET_BIAS 0x200U
/* The x86 boot header doesn't contain the length of the version string. 128 bytes contain the
 * "VERSION (USER@HOST) #" prefix of any real kernel. */
#define X86_KERNEL_VERSION_READ_MAX 128U
#define LINUX_ELFNOTE_BUILD_SALT 0x100U
/* The kernel stores its release in struct new_utsname, which has room for 64 characters. */
#define KERNEL_RELEASE_MAX 64U

static bool uname_is_valid(const char *s) {
        assert(s);

        /* The build salt and the banner search can produce strings that are not kernel releases. A kernel
         * release starts with the major version followed by a dot. */
        size_t d = strspn(s, DIGITS);
        if (d == 0 || s[d] != '.')
                return false;

        return strlen(s) <= KERNEL_RELEASE_MAX && version_is_valid(s, VERSION_ALLOW_UNDERSCORE|VERSION_ALLOW_PLUS);
}

int kernel_uname_from_x86_boot_header(int fd, char **ret) {
        SetupHeader hdr;
        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        n = pread(fd, &hdr, sizeof(hdr), offsetof(BootParams, hdr));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read x86 boot header: %m");
        if ((size_t) n < sizeof(hdr))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image is too small for an x86 boot header.");
        if (le32toh(hdr.header) != SETUP_MAGIC)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image has no x86 boot header.");

        uint16_t offset = le16toh(hdr.kernel_version);
        if (offset == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "x86 boot header does not contain the offset of the kernel version.");

        char text[X86_KERNEL_VERSION_READ_MAX + 1] = {};
        n = pread(fd, text, X86_KERNEL_VERSION_READ_MAX, X86_KERNEL_VERSION_OFFSET_BIAS + offset);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read kernel version from x86 boot header: %m");

        /* The string has the form "VERSION (USER@HOST) #BUILD ...". */
        size_t l = strspn(text, ALPHANUMERICAL "._+-");
        if (l == 0 || !startswith(text + l, " ("))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Kernel version in the x86 boot header is not followed by \" (\".");

        const char *p = text + l + 2;
        p += strcspn(p, " )");
        if (!startswith(p, ") #"))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Kernel version in the x86 boot header is not followed by \"(USER@HOST) #\".");

        _cleanup_free_ char *s = strndup(text, l);
        if (!s)
                return -ENOMEM;

        if (!uname_is_valid(s))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Kernel version '%s' in the x86 boot header is not valid.", s);

        *ret = TAKE_PTR(s);
        return 0;
}

static int uname_from_elf_note(const uint8_t *data, size_t size, char **ret) {
        assert(data || size == 0);
        assert(ret);

        /* The kernel stores CONFIG_BUILD_SALT in a note with the name "Linux" and the type
         * LINUX_ELFNOTE_BUILD_SALT. Some distributions set CONFIG_BUILD_SALT to the kernel version. Others
         * keep the upstream default, which is an empty string, or set another value. We only use the note
         * if it contains a valid version. */

        if (size < EI_NIDENT || memcmp(data, ELFMAG, SELFMAG) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image is not an ELF file.");

        if (!IN_SET(data[EI_CLASS], ELFCLASS32, ELFCLASS64) || !IN_SET(data[EI_DATA], ELFDATA2LSB, ELFDATA2MSB))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Kernel ELF file has unknown class %u or data encoding %u.",
                                       data[EI_CLASS], data[EI_DATA]);

        bool is_64 = data[EI_CLASS] == ELFCLASS64, le = data[EI_DATA] == ELFDATA2LSB;

#define READ16(p) (le ? unaligned_read_le16(p) : unaligned_read_be16(p))
#define READ32(p) (le ? unaligned_read_le32(p) : unaligned_read_be32(p))
#define READ64(p) (le ? unaligned_read_le64(p) : unaligned_read_be64(p))

        size_t ehdr_size = is_64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
        if (size < ehdr_size)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel ELF file is too small for an ELF header.");

        uint64_t phoff = is_64 ? READ64(data + offsetof(Elf64_Ehdr, e_phoff)) : READ32(data + offsetof(Elf32_Ehdr, e_phoff));
        uint16_t phentsize = READ16(data + (is_64 ? offsetof(Elf64_Ehdr, e_phentsize) : offsetof(Elf32_Ehdr, e_phentsize))),
                 phnum = READ16(data + (is_64 ? offsetof(Elf64_Ehdr, e_phnum) : offsetof(Elf32_Ehdr, e_phnum)));

        if (phentsize < (is_64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr)))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Kernel ELF file has program headers of %" PRIu16 " bytes, which is too small.",
                                       phentsize);

        /* Several program headers can refer to the same note segment. We stop once we have scanned as many
         * note bytes as the file contains, so that a crafted file can't make us scan the same segment
         * thousands of times. */
        uint64_t note_bytes_left = size;

        for (uint16_t i = 0; i < phnum; i++) {
                uint64_t ph = phoff + (uint64_t) i * phentsize;
                if (ph > size || size - ph < phentsize)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "Program header %" PRIu16 " of the kernel ELF file is outside of the file.", i);

                const uint8_t *p = data + ph;
                uint32_t type = READ32(p + (is_64 ? offsetof(Elf64_Phdr, p_type) : offsetof(Elf32_Phdr, p_type)));
                if (type != PT_NOTE)
                        continue;

                uint64_t offset = is_64 ? READ64(p + offsetof(Elf64_Phdr, p_offset)) : READ32(p + offsetof(Elf32_Phdr, p_offset)),
                         filesz = is_64 ? READ64(p + offsetof(Elf64_Phdr, p_filesz)) : READ32(p + offsetof(Elf32_Phdr, p_filesz));
                if (offset > size || filesz > size - offset) {
                        log_debug("Note segment %" PRIu16 " of the kernel ELF file is outside of the file, ignoring.", i);
                        continue;
                }

                if (filesz > note_bytes_left)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "Note segments of the kernel ELF file are larger than the file.");
                note_bytes_left -= filesz;

                for (uint64_t q = offset; q + 12 <= offset + filesz;) {
                        uint32_t namesz = READ32(data + q), descsz = READ32(data + q + 4), ntype = READ32(data + q + 8);
                        uint64_t name = q + 12, desc = name + ALIGN_TO_U64(namesz, 4), next = desc + ALIGN_TO_U64(descsz, 4);
                        if (next > offset + filesz) {
                                log_debug("Note in segment %" PRIu16 " of the kernel ELF file is outside of the segment, ignoring.", i);
                                break;
                        }

                        q = next;

                        if (ntype != LINUX_ELFNOTE_BUILD_SALT || namesz != 6 || memcmp(data + name, "Linux", 6) != 0)
                                continue;

                        if (descsz > KERNEL_RELEASE_MAX + 1) {
                                log_debug("Build salt note of the kernel ELF file has %" PRIu32 " bytes, which is too long for a kernel version, ignoring.", descsz);
                                continue;
                        }

                        size_t l = descsz;
                        while (l > 0 && data[desc + l - 1] == 0)
                                l--;

                        if (l == 0) {
                                log_debug("Build salt note of the kernel ELF file is empty, ignoring.");
                                continue;
                        }
                        if (memchr(data + desc, 0, l)) {
                                log_debug("Build salt note of the kernel ELF file contains a NUL byte, ignoring.");
                                continue;
                        }

                        _cleanup_free_ char *s = memdup_suffix0(data + desc, l);
                        if (!s)
                                return -ENOMEM;

                        if (!uname_is_valid(s)) {
                                log_debug("Build salt note of the kernel ELF file is not a kernel version, ignoring.");
                                continue;
                        }

                        *ret = TAKE_PTR(s);
                        return 0;
                }
        }

#undef READ16
#undef READ32
#undef READ64

        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel ELF file has no build salt note with a valid version.");
}

static int uname_from_banner(const uint8_t *data, size_t size, char **ret) {
        static const char banner[] = "Linux version ";

        assert(data || size == 0);
        assert(ret);

        /* Kernels for architectures other than x86 have no boot header that contains the version. The
         * uncompressed kernel contains linux_banner from init/version-timestamp.c instead. /proc/version
         * shows the same string. It has the form "Linux version VERSION (USER@HOST) (COMPILER) #BUILD
         * ...". ukify.py searches the decompressed kernel for the banner, so we do the same for
         * compatibility. */

        for (const uint8_t *p = data; p < data + size;) {
                p = memmem_safe(p, data + size - p, banner, strlen(banner));
                if (!p)
                        break;

                p += strlen(banner);

                size_t l = 0;
                while (l <= KERNEL_RELEASE_MAX && p + l < data + size && !strchr(WHITESPACE, p[l]))
                        l++;

                if (l == 0 || l > KERNEL_RELEASE_MAX || p + l + 2 > data + size || p[l] != ' ' || p[l + 1] != '(')
                        continue;

                _cleanup_free_ char *s = memdup_suffix0(p, l);
                if (!s)
                        return -ENOMEM;

                if (!uname_is_valid(s)) {
                        log_debug("Kernel banner does not contain a valid version, ignoring.");
                        continue;
                }

                *ret = TAKE_PTR(s);
                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image contains no kernel banner with a valid version.");
}

static int uname_from_image_data(
                int fd,
                int (*func)(const uint8_t *data, size_t size, char **ret),
                char **ret) {

        struct stat st;
        int r;

        assert(fd >= 0);
        assert(func);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat kernel image: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "Kernel image is not a regular file: %m");

        if (st.st_size == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Kernel image is empty.");
        if ((uint64_t) st.st_size > SIZE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "Kernel image is too large to map.");

        void *p = mmap(/* addr= */ NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, /* offset= */ 0);
        if (p == MAP_FAILED)
                return log_debug_errno(errno, "Failed to map kernel image: %m");

        r = func(p, st.st_size, ret);

        (void) munmap(p, st.st_size);
        return r;
}

int kernel_uname_from_elf_note(int fd, char **ret) {
        return uname_from_image_data(fd, uname_from_elf_note, ret);
}

int kernel_uname_from_banner(int fd, char **ret) {
        return uname_from_image_data(fd, uname_from_banner, ret);
}

int kernel_find_uname(int fd, char **ret) {
        _cleanup_close_ int decompressed_fd = -EBADF;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* fd can refer to an x86 bzImage, a ZBOOT EFI image, a vmlinux ELF file, an uncompressed kernel
         * image, or a kernel image compressed with a format that kernel_decompress() supports. UKIs are not
         * supported. inspect_kernel() reads the version from their .uname section. */

        r = kernel_uname_from_x86_boot_header(fd, ret);
        if (r != -ENODATA)
                return r;

        r = kernel_decompress(fd, &decompressed_fd);
        if (r < 0)
                return r;

        int data_fd = r > 0 ? decompressed_fd : fd;

        r = kernel_uname_from_elf_note(data_fd, ret);
        if (r != -ENODATA)
                return r;

        return kernel_uname_from_banner(data_fd, ret);
}
