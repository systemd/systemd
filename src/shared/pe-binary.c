/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "pe-binary.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"

/* Note: none of these function change the file position of the provided fd, as they use pread() */

bool pe_header_is_64bit(const PeHeader *h) {
        assert(h);

        if (le16toh(h->optional.Magic) == UINT16_C(0x010B)) /* PE32 */
                return false;

        if (le16toh(h->optional.Magic) == UINT16_C(0x020B)) /* PE32+ */
                return true;

        assert_not_reached();
}

static size_t pe_header_size(const PeHeader *pe_header) {
        assert(pe_header);

        return offsetof(PeHeader, optional) + le16toh(pe_header->pe.SizeOfOptionalHeader);
}

const IMAGE_DATA_DIRECTORY* pe_header_get_data_directory(
                const PeHeader *h,
                size_t i) {

        assert(h);

        if (i >= le32toh(PE_HEADER_OPTIONAL_FIELD(h, NumberOfRvaAndSizes)))
                return NULL;

        return PE_HEADER_OPTIONAL_FIELD(h, DataDirectory) + i;
}

const IMAGE_SECTION_HEADER* pe_section_table_find(
                const IMAGE_SECTION_HEADER *sections,
                size_t n_sections,
                const char *name) {

        size_t n;

        assert(name);
        assert(sections || n_sections == 0);

        n = strlen(name);
        if (n > sizeof(sections[0].Name)) /* Too long? */
                return NULL;

        FOREACH_ARRAY(section, sections, n_sections)
                if (memcmp(section->Name, name, n) == 0 &&
                    (n == sizeof(sections[0].Name) || memeqzero(section->Name + n, sizeof(section->Name) - n)))
                        return section;

        return NULL;
}

const IMAGE_SECTION_HEADER* pe_header_find_section(
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name) {

        assert(pe_header);

        return pe_section_table_find(sections, le16toh(pe_header->pe.NumberOfSections), name);
}

int pe_load_headers(
                int fd,
                IMAGE_DOS_HEADER **ret_dos_header,
                PeHeader **ret_pe_header) {

        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        ssize_t n;

        assert(fd >= 0);

        dos_header = new(IMAGE_DOS_HEADER, 1);
        if (!dos_header)
                return log_oom_debug();

        n = pread(fd,
                  dos_header,
                  sizeof(IMAGE_DOS_HEADER),
                  0);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read DOS header: %m");
        if ((size_t) n != sizeof(IMAGE_DOS_HEADER))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading MZ executable header.");

        if (le16toh(dos_header->e_magic) != UINT16_C(0x5A4D))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks MZ executable header.");

        pe_header = new(PeHeader, 1);
        if (!pe_header)
                return log_oom_debug();

        n = pread(fd,
                  pe_header,
                  offsetof(PeHeader, optional),
                  le32toh(dos_header->e_lfanew));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable header: %m");
        if ((size_t) n != offsetof(PeHeader, optional))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable header.");

        if (le32toh(pe_header->signature) != UINT32_C(0x00004550))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks PE executable header.");

        if (le16toh(pe_header->pe.SizeOfOptionalHeader) < sizeof_field(PeHeader, optional.Magic))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size too short for magic.");

        PeHeader *pe_header_tmp = realloc(pe_header, MAX(sizeof(PeHeader), pe_header_size(pe_header)));
        if (!pe_header_tmp)
                return log_oom_debug();
        pe_header = pe_header_tmp;

        n = pread(fd,
                  &pe_header->optional,
                  le16toh(pe_header->pe.SizeOfOptionalHeader),
                  le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable optional header: %m");
        if ((size_t) n != le16toh(pe_header->pe.SizeOfOptionalHeader))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable optional header.");

        if (!IN_SET(le16toh(pe_header->optional.Magic), UINT16_C(0x010B), UINT16_C(0x020B)))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header magic invalid.");

        if (pe_header_size(pe_header) !=
            PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory) +
            sizeof(IMAGE_DATA_DIRECTORY) * (uint64_t) le32toh(PE_HEADER_OPTIONAL_FIELD(pe_header, NumberOfRvaAndSizes)))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size mismatch.");

        if (ret_dos_header)
                *ret_dos_header = TAKE_PTR(dos_header);
        if (ret_pe_header)
                *ret_pe_header = TAKE_PTR(pe_header);

        return 0;
}

int pe_load_sections(
                int fd,
                const IMAGE_DOS_HEADER *dos_header,
                const PeHeader *pe_header,
                IMAGE_SECTION_HEADER **ret_sections) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        size_t nos;
        ssize_t n;

        assert(fd >= 0);
        assert(dos_header);
        assert(pe_header);

        nos = le16toh(pe_header->pe.NumberOfSections);

        sections = new(IMAGE_SECTION_HEADER, nos);
        if (!sections)
                return log_oom_debug();

        n = pread(fd,
                  sections,
                  sizeof(IMAGE_SECTION_HEADER) * nos,
                  le32toh(dos_header->e_lfanew) + pe_header_size(pe_header));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read section table: %m");
        if ((size_t) n != sizeof(IMAGE_SECTION_HEADER) * nos)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading section table.");

        if (ret_sections)
                *ret_sections = TAKE_PTR(sections);

        return 0;
}

int pe_read_section_data(
                int fd,
                const IMAGE_SECTION_HEADER *section,
                size_t max_size,
                void **ret,
                size_t *ret_size) {

        assert(fd >= 0);
        assert(section);

        size_t n = le32toh(section->VirtualSize);
        if (n > MIN(max_size, (size_t) SSIZE_MAX))
                return -E2BIG;

        _cleanup_free_ void *data = malloc(n+1);
        if (!data)
                return -ENOMEM;

        ssize_t ss = pread(fd, data, n, le32toh(section->PointerToRawData));
        if (ss < 0)
                return -errno;
        if ((size_t) ss != n)
                return -EIO;

        if (ret_size)
                *ret_size = n;
        else {
                /* Check that there are no embedded NUL bytes if the caller doesn't want to know the size
                 * (i.e. treats the blob as a string) */
                const char *nul;

                nul = memchr(data, 0, n);
                if (nul && !memeqzero(nul, n - (nul - (const char*) data))) /* If there's a NUL it must only be NULs from there on */
                        return -EBADMSG;
        }
        if (ret) {
                ((uint8_t*) data)[n] = 0; /* NUL terminate, no matter what */
                *ret = TAKE_PTR(data);
        }

        return 0;
}

int pe_read_section_data_by_name(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name,
                size_t max_size,
                void **ret,
                size_t *ret_size) {

        const IMAGE_SECTION_HEADER *section;

        assert(fd >= 0);
        assert(pe_header);
        assert(sections || pe_header->pe.NumberOfSections == 0);
        assert(name);

        section = pe_header_find_section(pe_header, sections, name);
        if (!section)
                return -ENXIO;

        return pe_read_section_data(fd, section, max_size, ret, ret_size);
}

bool pe_is_uki(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections) {
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (le16toh(pe_header->optional.Subsystem) != IMAGE_SUBSYSTEM_EFI_APPLICATION)
                return false;

        /* Note that the UKI spec only requires .linux, but we are stricter here, and require .osrel too,
         * since for sd-boot it just doesn't make sense to not have that. */
        return
                pe_header_find_section(pe_header, sections, ".osrel") &&
                pe_header_find_section(pe_header, sections, ".linux");
}

bool pe_is_addon(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections) {
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (le16toh(pe_header->optional.Subsystem) != IMAGE_SUBSYSTEM_EFI_APPLICATION)
                return false;

        /* Add-ons do not have a Linux kernel, but do have one of .cmdline, .dtb, .initrd or .ucode (currently) */
        return !pe_header_find_section(pe_header, sections, ".linux") &&
                (pe_header_find_section(pe_header, sections, ".cmdline") ||
                 pe_header_find_section(pe_header, sections, ".dtb") ||
                 pe_header_find_section(pe_header, sections, ".initrd") ||
                 pe_header_find_section(pe_header, sections, ".ucode"));
}

bool pe_is_native(const PeHeader *pe_header) {
        assert(pe_header);

#ifdef _IMAGE_FILE_MACHINE_NATIVE
        return le16toh(pe_header->pe.Machine) == _IMAGE_FILE_MACHINE_NATIVE;
#else
        return false;
#endif
}

int pe_is_native_fd(int fd) {
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        r = pe_load_headers(fd, /* ret_dos_header= */ NULL, &pe_header);
        if (r < 0)
                return r;

        return pe_is_native(pe_header);
}

/* Implements:
 *
 * https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
 * → Section "Calculating the PE Image Hash"
 */

#if HAVE_OPENSSL
static int hash_file(int fd, EVP_MD_CTX *md_ctx, uint64_t offset, uint64_t size) {
        uint8_t buffer[64*1024];

        log_debug("Hashing %" PRIu64 " @ %" PRIu64 " → %" PRIu64, size, offset, offset + size);

        while (size > 0) {
                size_t m = MIN(size, sizeof(buffer));
                ssize_t n;

                n = pread(fd, buffer, m, offset);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read file for hashing: %m");
                if ((size_t) n != m)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while hashing.");

                if (EVP_DigestUpdate(md_ctx, buffer, m) != 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unable to hash data.");

                offset += m;
                size -= m;
        }

        return 0;
}

static int section_offset_cmp(const IMAGE_SECTION_HEADER *a, const IMAGE_SECTION_HEADER *b) {
        return CMP(ASSERT_PTR(a)->PointerToRawData, ASSERT_PTR(b)->PointerToRawData);
}

int pe_hash(int fd,
            const EVP_MD *md,
            void **ret_hash,
            size_t *ret_hash_size) {

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        const IMAGE_DATA_DIRECTORY *certificate_table;
        struct stat st;
        uint64_t p, q;
        int r;

        assert(fd >= 0);
        assert(md);
        assert(ret_hash_size);
        assert(ret_hash);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat file: %m");
        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "Not a regular file: %m");

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return r;

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return r;

        certificate_table = pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        if (!certificate_table)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks certificate table.");

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
                return log_oom_debug();

        if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to allocate message digest.");

        /* Everything from beginning of file to CheckSum field in PE header */
        p = (uint64_t) dos_header->e_lfanew +
                offsetof(PeHeader, optional.CheckSum);
        r = hash_file(fd, mdctx, 0, p);
        if (r < 0)
                return r;
        p += sizeof(le32_t);

        /* Everything between the CheckSum field and the Image Data Directory Entry for the Certification Table */
        q = (uint64_t) dos_header->e_lfanew +
                PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory[IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE]);
        r = hash_file(fd, mdctx, p, q - p);
        if (r < 0)
                return r;
        q += sizeof(IMAGE_DATA_DIRECTORY);

        /* The rest of the header + the section table */
        p = pe_header->optional.SizeOfHeaders;
        if (p < q)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "SizeOfHeaders too short.");
        r = hash_file(fd, mdctx, q, p - q);
        if (r < 0)
                return r;

        /* Sort by location in file */
        typesafe_qsort(sections, pe_header->pe.NumberOfSections, section_offset_cmp);

        FOREACH_ARRAY(section, sections, pe_header->pe.NumberOfSections) {
                r = hash_file(fd, mdctx, section->PointerToRawData, section->SizeOfRawData);
                if (r < 0)
                        return r;

                p += section->SizeOfRawData;
        }

        if ((uint64_t) st.st_size > p) {

                if (st.st_size - p < certificate_table->Size)
                        return log_debug_errno(errno, "No space for certificate table, refusing.");

                r = hash_file(fd, mdctx, p, st.st_size - p - certificate_table->Size);
                if (r < 0)
                        return r;

                /* If the file size is not a multiple of 8 bytes, pad the hash with zero bytes. */
                if (st.st_size % 8 != 0 && EVP_DigestUpdate(mdctx, (const uint8_t[8]) {}, 8 - (st.st_size % 8)) != 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unable to hash data.");
        }

        int hsz = EVP_MD_CTX_size(mdctx);
        if (hsz < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to get hash size.");

        unsigned hash_size = (unsigned) hsz;
        _cleanup_free_ void *hash = malloc(hsz);
        if (!hash)
                return log_oom_debug();

        if (EVP_DigestFinal_ex(mdctx, hash, &hash_size) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to finalize hash function.");

        assert(hash_size == (unsigned) hsz);

        *ret_hash = TAKE_PTR(hash);
        *ret_hash_size = hash_size;

        return 0;
}

int pe_checksum(int fd, uint32_t *ret) {
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat file: %m");

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return r;

        uint32_t checksum = 0, checksum_offset = le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional.CheckSum);
        size_t off = 0;
        for (;;) {
                uint16_t buf[32*1024];

                ssize_t n = pread(fd, buf, sizeof(buf), off);
                if (n == 0)
                        break;
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read from PE file: %m");
                if (n % sizeof(uint16_t) != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short read from PE file");

                for (size_t i = 0; i < (size_t) n / 2; i++) {
                        if (off + i >= checksum_offset && off + i < checksum_offset + sizeof(pe_header->optional.CheckSum))
                                continue;

                        uint16_t val = le16toh(buf[i]);

                        checksum += val;
                        checksum = (checksum >> 16) + (checksum & 0xffff);
                }

                off += n;
        }

        checksum = (checksum >> 16) + (checksum & 0xffff);
        checksum += off;

        *ret = checksum;
        return 0;
}

typedef void* SectionHashArray[_UNIFIED_SECTION_MAX];

static void section_hash_array_done(SectionHashArray *array) {
        assert(array);

        for (size_t i = 0; i < _UNIFIED_SECTION_MAX; i++)
                free((*array)[i]);
}

int uki_hash(int fd,
             const EVP_MD *md,
             void* ret_hashes[static _UNIFIED_SECTION_MAX],
             size_t *ret_hash_size) {

        _cleanup_(section_hash_array_done) SectionHashArray hashes = {};
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        assert(fd >= 0);
        assert(ret_hashes);
        assert(ret_hash_size);

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return r;

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return r;

        int hsz = EVP_MD_size(md);
        if (hsz < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to get hash size.");

        FOREACH_ARRAY(section, sections, pe_header->pe.NumberOfSections) {
                _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;
                _cleanup_free_ char *n = NULL;
                ssize_t i;

                n = memdup_suffix0(section->Name, sizeof(section->Name));
                if (!n)
                        return log_oom_debug();

                i = string_table_lookup_from_string(unified_sections, _UNIFIED_SECTION_MAX, n);
                if (i < 0)
                        continue;

                if (hashes[i])
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Duplicate section");

                mdctx = EVP_MD_CTX_new();
                if (!mdctx)
                        return log_oom_debug();

                if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to allocate message digest.");

                r = hash_file(fd, mdctx, section->PointerToRawData, MIN(section->VirtualSize, section->SizeOfRawData));
                if (r < 0)
                        return r;

                if (section->SizeOfRawData < section->VirtualSize) {
                        uint8_t zeroes[1024] = {};
                        size_t remaining = section->VirtualSize - section->SizeOfRawData;

                        while (remaining > 0) {
                                size_t sz = MIN(sizeof(zeroes), remaining);

                                if (EVP_DigestUpdate(mdctx, zeroes, sz) != 1)
                                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unable to hash data.");

                                remaining -= sz;
                        }
                }

                hashes[i] = malloc(hsz);
                if (!hashes[i])
                        return log_oom_debug();

                unsigned hash_size = (unsigned) hsz;
                if (EVP_DigestFinal_ex(mdctx, hashes[i], &hash_size) != 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to finalize hash function.");

                assert(hash_size == (unsigned) hsz);

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *hs = NULL;

                        hs = hexmem(hashes[i], hsz);
                        log_debug("Section %s with %s is %s.", n, EVP_MD_name(md), strna(hs));
                }
        }

        memcpy(ret_hashes, hashes, sizeof(hashes));
        zero(hashes);
        *ret_hash_size = (unsigned) hsz;

        return 0;
}
#endif
