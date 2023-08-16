/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>
#include <sys/stat.h>

#include "fd-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "openssl-util.h"
#include "pehash.h"
#include "sort-util.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"

/* Implements:
 *
 * https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
 * → Section "Calculating the PE Image Hash"
 */

typedef struct _IMAGE_DOS_HEADER {
        le16_t e_magic;
        le16_t e_cblp;
        le16_t e_cp;
        le16_t e_crlc;
        le16_t e_cparhdr;
        le16_t e_minalloc;
        le16_t e_maxalloc;
        le16_t e_ss;
        le16_t e_sp;
        le16_t e_csum;
        le16_t e_ip;
        le16_t e_cs;
        le16_t e_lfarlc;
        le16_t e_ovno;
        le16_t e_res[4];
        le16_t e_oemid;
        le16_t e_oeminfo;
        le16_t e_res2[10];
        le32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
        le16_t Machine;
        le16_t NumberOfSections;
        le32_t TimeDateStamp;
        le32_t PointerToSymbolTable;
        le32_t NumberOfSymbols;
        le16_t SizeOfOptionalHeader;
        le16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
        le32_t VirtualAddress;
        le32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER_32 {
        /* Standard fields */
        le16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        le32_t SizeOfCode;
        le32_t SizeOfInitializedData;
        le32_t SizeOfUninitializedData;
        le32_t AddressOfEntryPoint;
        le32_t BaseOfCode;
        le32_t BaseOfData;

        /* Additional fields */
        le32_t ImageBase;
        le32_t SectionAlignment;
        le32_t FileAlignment;
        le16_t MajorOperatingSystemVersion;
        le16_t MinorOperatingSystemVersion;
        le16_t MajorImageVersion;
        le16_t MinorImageVersion;
        le16_t MajorSubsystemVersion;
        le16_t MinorSubsystemVersion;
        le32_t Reserved1;
        le32_t SizeOfImage;
        le32_t SizeOfHeaders;
        le32_t CheckSum;
        le16_t Subsystem;
        le16_t DllCharacteristics;
        le32_t SizeOfStackReserve;
        le32_t SizeOfStackCommit;
        le32_t SizeOfHeapReserve;
        le32_t SizeOfHeapCommit;
        le32_t LoaderFlags;
        le32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_32;

typedef struct _IMAGE_OPTIONAL_HEADER_64 {
        /* Standard fields */
        le16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        le32_t SizeOfCode;
        le32_t SizeOfInitializedData;
        le32_t SizeOfUninitializedData;
        le32_t AddressOfEntryPoint;
        le32_t BaseOfCode;

        /* Additional fields */
        le64_t ImageBase;
        le32_t SectionAlignment;
        le32_t FileAlignment;
        le16_t MajorOperatingSystemVersion;
        le16_t MinorOperatingSystemVersion;
        le16_t MajorImageVersion;
        le16_t MinorImageVersion;
        le16_t MajorSubsystemVersion;
        le16_t MinorSubsystemVersion;
        le32_t Reserved1;
        le32_t SizeOfImage;
        le32_t SizeOfHeaders;
        le32_t CheckSum;
        le16_t Subsystem;
        le16_t DllCharacteristics;
        le64_t SizeOfStackReserve;
        le64_t SizeOfStackCommit;
        le64_t SizeOfHeapReserve;
        le64_t SizeOfHeapCommit;
        le32_t LoaderFlags;
        le32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_64;

typedef union IMAGE_OPTIONAL_HEADER_UNION {
        IMAGE_OPTIONAL_HEADER_32 o32;
        IMAGE_OPTIONAL_HEADER_64 o64;
        le16_t Magic;
} IMAGE_OPTIONAL_HEADER_UNION;

typedef struct PeHeader {
        le32_t signature;
        IMAGE_FILE_HEADER pe;
        IMAGE_OPTIONAL_HEADER_UNION optional;
} PeHeader;

typedef struct _IMAGE_SECTION_HEADER {
        uint8_t Name[8];
        le32_t VirtualSize;
        le32_t VirtualAddress;
        le32_t SizeOfRawData;
        le32_t PointerToRawData;
        le32_t PointerToRelocations;
        le32_t PointerToLinenumbers;
        le16_t NumberOfRelocations;
        le16_t NumberOfLinenumbers;
        le32_t Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE 4U

static bool pe_header_is_64bit(const PeHeader *h) {
        assert(h);

        if (h->optional.Magic == UINT16_C(0x010B)) /* PE32 */
                return false;

        if (h->optional.Magic == UINT16_C(0x020B)) /* PE32+ */
                return true;

        assert_not_reached();
}

#define PE_HEADER_OPTIONAL_FIELD(h, field)                           \
        (*(pe_header_is_64bit(h) ? &(h)->optional.o64.field : &(h)->optional.o32.field))

#define PE_HEADER_OPTIONAL_FIELD_OFFSET(h, field) \
        (pe_header_is_64bit(h) ? offsetof(PeHeader, optional.o64.field) : offsetof(PeHeader, optional.o32.field))

static IMAGE_DATA_DIRECTORY *pe_header_get_data_directory(PeHeader *h, size_t i) {
        assert(h);

        if (i >= PE_HEADER_OPTIONAL_FIELD(h, NumberOfRvaAndSizes))
                return NULL;

        return PE_HEADER_OPTIONAL_FIELD(h, DataDirectory) + i;
}

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
        return CMP(a->PointerToRawData, b->PointerToRawData);
}

static int pe_load_headers(
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

        if (dos_header->e_magic != UINT16_C(0x5A4D))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks MZ executable header.");

        pe_header = new(PeHeader, 1);
        if (!pe_header)
                return log_oom_debug();

        n = pread(fd,
                  pe_header,
                  offsetof(PeHeader, optional),
                  dos_header->e_lfanew);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable header: %m");
        if ((size_t) n != offsetof(PeHeader, optional))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable header.");

        if (pe_header->signature != UINT32_C(0x00004550))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks PE executable header.");

        if (pe_header->pe.SizeOfOptionalHeader < sizeof_field(PeHeader, optional.Magic))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size too short for magic.");

        PeHeader *pe_header_tmp = realloc(
                        pe_header,
                        MAX(sizeof(PeHeader),
                            offsetof(PeHeader, optional) + pe_header->pe.SizeOfOptionalHeader));
        if (!pe_header_tmp)
                return log_oom_debug();
        pe_header = pe_header_tmp;

        n = pread(fd,
                  &pe_header->optional,
                  pe_header->pe.SizeOfOptionalHeader,
                  dos_header->e_lfanew + offsetof(PeHeader, optional));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable optional header: %m");
        if ((size_t) n != pe_header->pe.SizeOfOptionalHeader)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable optional header.");

        if (!IN_SET(pe_header->optional.Magic, UINT16_C(0x010B), UINT16_C(0x020B)))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header magic invalid.");

        if (offsetof(PeHeader, optional) + pe_header->pe.SizeOfOptionalHeader !=
            PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory) +
            sizeof(IMAGE_DATA_DIRECTORY) * (uint64_t) PE_HEADER_OPTIONAL_FIELD(pe_header, NumberOfRvaAndSizes))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size mismatch.");

        if (ret_dos_header)
                *ret_dos_header = TAKE_PTR(dos_header);
        if (ret_pe_header)
                *ret_pe_header = TAKE_PTR(pe_header);

        return 0;
}

static int pe_load_sections(
                int fd,
                const IMAGE_DOS_HEADER *dos_header,
                const PeHeader *pe_header,
                IMAGE_SECTION_HEADER **ret_sections) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ssize_t n;

        assert(fd >= 0);
        assert(dos_header);
        assert(pe_header);

        sections = new(IMAGE_SECTION_HEADER, pe_header->pe.NumberOfSections);
        if (!sections)
                return log_oom_debug();

        n = pread(fd,
                  sections,
                  sizeof(IMAGE_SECTION_HEADER) * pe_header->pe.NumberOfSections,
                  dos_header->e_lfanew + offsetof(PeHeader, optional) + pe_header->pe.SizeOfOptionalHeader);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read section table: %m");
        if ((size_t) n != sizeof(IMAGE_SECTION_HEADER) * pe_header->pe.NumberOfSections)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading section table.");

        if (ret_sections)
                *ret_sections = TAKE_PTR(sections);

        return 0;
}

int pe_hash(int fd,
            const EVP_MD *md,
            void **ret_hash,
            size_t *ret_hash_size) {

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        IMAGE_DATA_DIRECTORY *certificate_table;
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
                PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, CheckSum);
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
        p = PE_HEADER_OPTIONAL_FIELD(pe_header, SizeOfHeaders);
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
        }

        int hsz = EVP_MD_CTX_get_size(mdctx);
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

typedef void* SectionHashArray[_UNIFIED_SECTION_MAX];

static void free_section_hashes(SectionHashArray *array) {
        for (size_t i = 0; i < _UNIFIED_SECTION_MAX; i++)
                free((*array)[i]);
}

int uki_hash(int fd,
             const EVP_MD *md,
             void* ret_hashes[static _UNIFIED_SECTION_MAX],
             size_t *ret_hash_size) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_(free_section_hashes) SectionHashArray hashes = {};
        int r;

        assert(fd);
        assert(ret_hashes);
        assert(ret_hash_size);

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return r;

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return r;

        int hsz = EVP_MD_get_size(md);
        if (hsz < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to get hash size.");

        FOREACH_ARRAY(section, sections, pe_header->pe.NumberOfSections) {
                _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;
                _cleanup_free_ char *n = NULL;
                ssize_t i;

                n = memdup_suffix0(section->Name, sizeof(section->Name));
                if (!n)
                        return log_oom_debug();

                i = string_table_lookup(unified_sections, _UNIFIED_SECTION_MAX, n);
                if (i < 0)
                        continue;

                if (hashes[i])
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Duplicate section");

                mdctx = EVP_MD_CTX_new();
                if (!mdctx)
                        return log_oom_debug();

                if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to allocate message digest.");

                r = hash_file(fd, mdctx, section->PointerToRawData, section->VirtualSize);
                if (r < 0)
                        return r;

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
                        log_debug("Section %s with %s is %s.", n, EVP_MD_get0_name(md), strna(hs));
                }
        }

        memcpy(ret_hashes, hashes, sizeof(hashes));
        zero(hashes);
        *ret_hash_size = (unsigned) hsz;

        return 0;
}
