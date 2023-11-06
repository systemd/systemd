/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "hexdecoct.h"
#include "pe-binary.h"
#include "pehash.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"

/* Implements:
 *
 * https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
 * → Section "Calculating the PE Image Hash"
 */

#define IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE 4U

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
                        log_debug("Section %s with %s is %s.", n, EVP_MD_name(md), strna(hs));
                }
        }

        memcpy(ret_hashes, hashes, sizeof(hashes));
        zero(hashes);
        *ret_hash_size = (unsigned) hsz;

        return 0;
}
