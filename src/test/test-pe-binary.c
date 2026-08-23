/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Regression tests for the algorithmic-complexity DoS fix in src/shared/pe-binary.c
 * (issue #42344 — PE file with attacker-controlled VirtualSize wedges uki_hash
 * in an unbounded SHA-256 zero-padding loop).
 *
 * Coverage:
 *   - pe_load_sections() rejects sections whose PointerToRawData + SizeOfRawData
 *     exceeds the actual file size (PLAN §3.1).
 *   - uki_hash() refuses to hash a section whose VirtualSize exceeds
 *     SizeOfRawData by more than UKI_HASH_VIRTUAL_SIZE_PADDING_MAX (=64 MiB)
 *     and instead returns -EBADMSG (PLAN §3.2).
 *
 * Tests build small PE32+ images in a memfd. The header layout mirrors the
 * canonical 382-byte reproducer (DOS at 0x00, e_lfanew=0x40, PE32+ optional
 * header of 0xf0 bytes, section table starting at file offset 0x148) so
 * pe_load_headers() accepts every test fixture; only the section table and
 * file size are varied per test. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "pe-binary.h"
#include "tests.h"
#include "uki.h"
#include "unaligned.h"

#if HAVE_OPENSSL
#  include "crypto-util.h"
#endif

/* Match the cap defined in src/shared/pe-binary.c (PLAN §3.2). */
#define UKI_HASH_PADDING_CAP_BYTES (64U * 1024U * 1024U)

/* File offsets of the PE32+ header skeleton this test builds. */
#define SECTION_TABLE_OFFSET 0x148
#define IMAGE_FILE_HEADER_NOS_OFFSET 0x46    /* NumberOfSections (le16) */
#define IMAGE_SECTION_HEADER_BYTES 40

/* Header skeleton, byte-for-byte compatible with the canonical reproducer
 * so that pe_load_headers() succeeds without further mutation. We only
 * patch NumberOfSections at runtime (offset 0x46) and append section
 * headers + raw data after the optional header. */
static const uint8_t HEADER_SKELETON[SECTION_TABLE_OFFSET] = {
        /* DOS header: "MZ" at 0x00, e_lfanew = 0x40 at 0x3c */
        [0x00] = 'M', 'Z',
        [0x3c] = 0x40, 0x00, 0x00, 0x00,

        /* PE signature at 0x40 */
        [0x40] = 'P', 'E', 0x00, 0x00,

        /* IMAGE_FILE_HEADER at 0x44 */
        [0x44] = 0x64, 0x86,                  /* Machine = 0x8664 (x86_64) */
        /* [0x46]: NumberOfSections — patched per test */
        [0x54] = 0xf0, 0x00,                  /* SizeOfOptionalHeader = 0xf0 */
        [0x56] = 0x22, 0x00,                  /* Characteristics = executable image */

        /* IMAGE_OPTIONAL_HEADER (PE32+) at 0x58 */
        [0x58] = 0x0b, 0x02,                  /* Magic = 0x020b (PE32+) */
        [0x9c] = 0x0a, 0x00,                  /* Subsystem = EFI Application */
        [0xc4] = 0x10, 0x00, 0x00, 0x00,      /* NumberOfRvaAndSizes = 16 (matches SizeOfOptionalHeader=0xf0) */
};

typedef struct SectionSpec {
        const char *name;       /* PE section name; truncated/padded to 8 bytes on write */
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
} SectionSpec;

/* Build a PE32+ image in a fresh memfd containing the given sections.
 *
 * If override_file_size > 0, the memfd is written with exactly that many
 * bytes (zero-padded if larger than what the sections need). This lets a
 * test claim section data past the actual EOF, or reserve headroom past
 * the last section. If 0, the file is sized to exactly contain the
 * headers + section table + every section's raw data. */
static int build_pe_file(
                const SectionSpec *specs,
                size_t n_sections,
                size_t override_file_size) {

        /* Minimum size is "headers + section table"; sections with SizeOfRawData>0
         * must additionally fit inside the file. */
        size_t base = SECTION_TABLE_OFFSET + n_sections * IMAGE_SECTION_HEADER_BYTES;
        size_t needed = base;
        FOREACH_ARRAY(spec, specs, n_sections)
                if (spec->size_of_raw_data > 0) {
                        uint64_t end = (uint64_t) spec->pointer_to_raw_data + spec->size_of_raw_data;
                        if (end > needed)
                                needed = end;
                }

        size_t file_size = override_file_size > 0 ? override_file_size : needed;
        ASSERT_GE(file_size, base);
        _cleanup_free_ uint8_t *buf = ASSERT_NOT_NULL(new0(uint8_t, file_size));

        memcpy(buf, HEADER_SKELETON, sizeof(HEADER_SKELETON));
        unaligned_write_le16(buf + IMAGE_FILE_HEADER_NOS_OFFSET, (uint16_t) n_sections);

        /* Section table at 0x148. */
        FOREACH_ARRAY(spec, specs, n_sections) {
                uint8_t *sh = buf + SECTION_TABLE_OFFSET + (spec - specs) * IMAGE_SECTION_HEADER_BYTES;
                size_t nlen = strnlen(spec->name, 8);
                memcpy(sh, spec->name, nlen);
                unaligned_write_le32(sh + 8,  spec->virtual_size);
                unaligned_write_le32(sh + 12, spec->virtual_address);
                unaligned_write_le32(sh + 16, spec->size_of_raw_data);
                unaligned_write_le32(sh + 20, spec->pointer_to_raw_data);
                /* Characteristics, relocs, etc., left zero. */
        }

        int fd = ASSERT_OK(memfd_new("test-pe-binary"));

        /* Write only file_size bytes — that lets the caller construct a
         * PE whose section table claims data past EOF. */
        ASSERT_OK_EQ_ERRNO(write(fd, buf, file_size), (ssize_t) file_size);
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        return fd;
}

static int load_headers_and_sections(
                int fd,
                IMAGE_DOS_HEADER **ret_dos,
                PeHeader **ret_pe,
                IMAGE_SECTION_HEADER **ret_sections) {

        int r = pe_load_headers(fd, ret_dos, ret_pe);
        if (r < 0)
                return r;
        return pe_load_sections(fd, *ret_dos, *ret_pe, ret_sections);
}

/* ======================================================================
 * pe_load_headers — SizeOfOptionalHeader / NumberOfRvaAndSizes bound
 * ====================================================================== */

/* If SizeOfOptionalHeader is so small that pread() does not actually
 * populate NumberOfRvaAndSizes, the optional-header size check at the end
 * of pe_load_headers would read uninitialised heap memory (caught by MSAN
 * under CIFuzz). pe_load_headers must reject such files with -EBADMSG
 * before touching that field. */
TEST(pe_load_headers_optional_header_too_small) {
        /* Minimum allowed by the existing magic check is 2 bytes (only
         * IMAGE_OPTIONAL_HEADER.Magic). That is well below the
         * NumberOfRvaAndSizes offset for both PE32 and PE32+. */
        uint8_t buf[64 + 4 + 20 + 2] = {};   /* DOS + PE sig + file hdr + 2-byte optional */
        buf[0] = 'M'; buf[1] = 'Z';
        unaligned_write_le32(buf + 0x3c, 64);
        memcpy(buf + 64, "PE\0\0", 4);
        /* IMAGE_FILE_HEADER: leave most fields zero, set
         * SizeOfOptionalHeader = 2 (offset 0x10 within IMAGE_FILE_HEADER). */
        unaligned_write_le16(buf + 64 + 4 + 16, 2);
        /* Optional header Magic = 0x020B (PE32+). */
        unaligned_write_le16(buf + 64 + 4 + 20, 0x020B);

        _cleanup_close_ int fd = ASSERT_OK(memfd_new("test-pe-binary"));
        ASSERT_OK_EQ_ERRNO(write(fd, buf, sizeof(buf)), (ssize_t) sizeof(buf));
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));

        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        ASSERT_ERROR(pe_load_headers(fd, &dos, &pe), EBADMSG);
}

/* ======================================================================
 * pe_load_sections — bounds check from PLAN §3.1
 * ====================================================================== */

/* Happy path: a section whose raw data fits comfortably inside the file
 * (i.e. file has plenty of trailing headroom beyond the section). */
TEST(pe_load_sections_valid_in_bounds) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 16,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = SECTION_TABLE_OFFSET + IMAGE_SECTION_HEADER_BYTES,
        };
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, /* override_file_size= */ 4096);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* Boundary: PointerToRawData + SizeOfRawData == file_size is OK. */
TEST(pe_load_sections_section_exactly_fills_file) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 16,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = SECTION_TABLE_OFFSET + IMAGE_SECTION_HEADER_BYTES,
        };
        size_t exact_size = (size_t) s.pointer_to_raw_data + s.size_of_raw_data;
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, exact_size);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* Section's raw data claims to extend one byte past EOF — must be rejected. */
TEST(pe_load_sections_section_past_eof_by_one) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 16,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = SECTION_TABLE_OFFSET + IMAGE_SECTION_HEADER_BYTES,
        };
        size_t short_size = (size_t) s.pointer_to_raw_data + s.size_of_raw_data - 1;
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, short_size);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_ERROR(load_headers_and_sections(fd, &dos, &pe, &sections), EBADMSG);
}

/* PointerToRawData itself already past EOF, with non-zero SizeOfRawData. */
TEST(pe_load_sections_pointer_way_past_eof) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 16,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = UINT32_C(0x10000000),
        };
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, /* override_file_size= */ 4096);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_ERROR(load_headers_and_sections(fd, &dos, &pe, &sections), EBADMSG);
}

/* SizeOfRawData == 0 means "BSS-equivalent / uninitialised"; PointerToRawData
 * is a don't-care and must NOT be bounds-checked, even when nonsense. */
TEST(pe_load_sections_size_zero_with_huge_pointer) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 0x100,
                .size_of_raw_data = 0,
                .pointer_to_raw_data = UINT32_MAX,
        };
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* SizeOfRawData == 0 with PointerToRawData == 0 — most natural BSS case. */
TEST(pe_load_sections_size_zero_pointer_zero) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 0x40,
                .size_of_raw_data = 0,
                .pointer_to_raw_data = 0,
        };
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* PointerToRawData + SizeOfRawData overflows uint32 (both near UINT32_MAX).
 * The fix uses uint64 arithmetic + __builtin_add_overflow, so this must be
 * rejected, not silently wrap. */
TEST(pe_load_sections_uint32_overflow_sum) {
        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = UINT32_C(0xffffffff),
                .size_of_raw_data = UINT32_C(0x80000000),
                .pointer_to_raw_data = UINT32_C(0x80000000),
        };
        /* uint32 sum wraps to 0, but uint64 sum = 0x100000000 — must still
         * be rejected against a tiny file. */
        _cleanup_close_ int fd = build_pe_file(&s, /* n_sections= */ 1, /* override_file_size= */ 4096);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_ERROR(load_headers_and_sections(fd, &dos, &pe, &sections), EBADMSG);
}

/* Zero sections: bounds check loop runs zero times, fstat still succeeds. */
TEST(pe_load_sections_zero_sections) {
        _cleanup_close_ int fd = build_pe_file(NULL, /* n_sections= */ 0, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* Multiple sections, all valid — happy path with N>1. */
TEST(pe_load_sections_multi_all_valid) {
        size_t base = SECTION_TABLE_OFFSET + 3 * IMAGE_SECTION_HEADER_BYTES;
        SectionSpec specs[3] = {
                { .name = ".linux",   .virtual_size = 16,  .size_of_raw_data = 16,
                  .pointer_to_raw_data = (uint32_t) base },
                { .name = ".initrd",  .virtual_size = 8,   .size_of_raw_data = 8,
                  .pointer_to_raw_data = (uint32_t) (base + 16) },
                { .name = ".cmdline", .virtual_size = 0,   .size_of_raw_data = 0,
                  .pointer_to_raw_data = 0 },
        };
        _cleanup_close_ int fd = build_pe_file(specs, /* n_sections= */ 3, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));
}

/* Multiple sections; one of them claims data past EOF — the whole file
 * must be rejected, not just that section silently skipped. */
TEST(pe_load_sections_multi_one_past_eof) {
        size_t base = SECTION_TABLE_OFFSET + 3 * IMAGE_SECTION_HEADER_BYTES;
        SectionSpec specs[3] = {
                { .name = ".linux",   .virtual_size = 16, .size_of_raw_data = 16,
                  .pointer_to_raw_data = (uint32_t) base },
                { .name = ".initrd",  .virtual_size = 8,  .size_of_raw_data = 8,
                  .pointer_to_raw_data = (uint32_t) (base + 16) },
                { .name = ".cmdline", .virtual_size = 32, .size_of_raw_data = 32,
                  .pointer_to_raw_data = UINT32_C(0x40000000) },   /* nonsense */
        };
        _cleanup_close_ int fd = build_pe_file(specs, /* n_sections= */ 3, /* override_file_size= */ 4096);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_ERROR(load_headers_and_sections(fd, &dos, &pe, &sections), EBADMSG);
}

/* ======================================================================
 * uki_hash — zero-padding cap from PLAN §3.2
 * ====================================================================== */

#if HAVE_OPENSSL

/* Helper: call uki_hash on a freshly built single-section PE. Returns the
 * uki_hash() return value; any allocated hashes are freed. */
static int call_uki_hash_with(SectionSpec spec) {
        _cleanup_close_ int fd = build_pe_file(&spec, /* n_sections= */ 1, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        int r = load_headers_and_sections(fd, &dos, &pe, &sections);
        if (r < 0)
                return r;

        void *hashes[_UNIFIED_SECTION_MAX] = {};
        size_t hash_size = 0;
        r = uki_hash(fd, sym_EVP_sha256(), hashes, &hash_size);
        free_many(hashes, _UNIFIED_SECTION_MAX);
        return r;
}

/* No padding needed (VirtualSize == SizeOfRawData) — the cap branch is
 * skipped entirely; hash succeeds. */
TEST_RET(uki_hash_no_padding) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 16,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = SECTION_TABLE_OFFSET + IMAGE_SECTION_HEADER_BYTES,
        };
        ASSERT_OK(call_uki_hash_with(s));
        return EXIT_SUCCESS;
}

/* One-byte padding — well below the cap. Must succeed. */
TEST_RET(uki_hash_one_byte_padding) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = 17,
                .size_of_raw_data = 16,
                .pointer_to_raw_data = SECTION_TABLE_OFFSET + IMAGE_SECTION_HEADER_BYTES,
        };
        ASSERT_OK(call_uki_hash_with(s));
        return EXIT_SUCCESS;
}

/* Boundary: VirtualSize - SizeOfRawData == cap (64 MiB) — must succeed
 * (PLAN §4 says the comparison is strict ">"). SHA-256 of 64 MiB of zeros
 * is ~100–200 ms on a modern CPU but can be much slower on emulated arches,
 * so gate behind the slow-tests opt-in. */
TEST_RET(uki_hash_at_cap_boundary) {
        if (!slow_tests_enabled())
                return log_tests_skipped("slow tests disabled");
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = UKI_HASH_PADDING_CAP_BYTES,
                .size_of_raw_data = 0,
                .pointer_to_raw_data = 0,
        };
        ASSERT_OK(call_uki_hash_with(s));
        return EXIT_SUCCESS;
}

/* One byte over the cap — must be rejected with -EBADMSG. */
TEST_RET(uki_hash_one_over_cap_rejected) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = UKI_HASH_PADDING_CAP_BYTES + 1,
                .size_of_raw_data = 0,
                .pointer_to_raw_data = 0,
        };
        ASSERT_ERROR(call_uki_hash_with(s), EBADMSG);
        return EXIT_SUCCESS;
}

/* VirtualSize == UINT32_MAX, SizeOfRawData == 0. This is the worst-case
 * shape an attacker can produce: ~4 GiB of zero-padding. Without the cap
 * this is the >10 s wedge from #42344; with the cap it must return
 * -EBADMSG essentially instantly. */
TEST_RET(uki_hash_max_virtual_size_rejected) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = UINT32_MAX,
                .size_of_raw_data = 0,
                .pointer_to_raw_data = 0,
        };
        ASSERT_ERROR(call_uki_hash_with(s), EBADMSG);
        return EXIT_SUCCESS;
}

/* Reproduces the exact section shape of the canonical 382-byte slow-unit
 * (.initrd VS=0xff000000 RSD=0). Pre-fix this drove ~8.5 s of SHA-256; the
 * cap must reject it instantly. This is the in-code analogue of the
 * regression input pinned in test/fuzz/fuzz-pe-binary/. */
TEST_RET(uki_hash_canonical_42344_reproducer_pattern) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        SectionSpec s = {
                .name = ".initrd",
                .virtual_size = UINT32_C(0xff000000),
                .size_of_raw_data = 0,
                .pointer_to_raw_data = 0,
        };
        ASSERT_ERROR(call_uki_hash_with(s), EBADMSG);
        return EXIT_SUCCESS;
}

/* Multiple sections, one of which trips the cap — uki_hash() must abort
 * the entire call (return -EBADMSG) rather than silently skipping. */
TEST_RET(uki_hash_one_bad_among_many_rejected) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        size_t base = SECTION_TABLE_OFFSET + 2 * IMAGE_SECTION_HEADER_BYTES;
        SectionSpec specs[2] = {
                { .name = ".linux",  .virtual_size = 16, .size_of_raw_data = 16,
                  .pointer_to_raw_data = (uint32_t) base },
                { .name = ".initrd", .virtual_size = UKI_HASH_PADDING_CAP_BYTES + 1,
                  .size_of_raw_data = 0, .pointer_to_raw_data = 0 },
        };
        _cleanup_close_ int fd = build_pe_file(specs, /* n_sections= */ 2, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));

        void *hashes[_UNIFIED_SECTION_MAX] = {};
        size_t hash_size = 0;
        ASSERT_ERROR(uki_hash(fd, sym_EVP_sha256(), hashes, &hash_size), EBADMSG);
        free_many(hashes, _UNIFIED_SECTION_MAX);
        return EXIT_SUCCESS;
}

/* Sanity check: uki_hash on a "no UKI sections present" PE doesn't hit
 * the cap path at all (no section with VS>SRD that matches the unified
 * sections table). Just confirms the cap doesn't reject the empty case. */
TEST_RET(uki_hash_empty_pe_does_not_reject) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return log_tests_skipped("openssl not available");

        _cleanup_close_ int fd = build_pe_file(NULL, /* n_sections= */ 0, /* override_file_size= */ 0);
        _cleanup_free_ IMAGE_DOS_HEADER *dos = NULL;
        _cleanup_free_ PeHeader *pe = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        ASSERT_OK(load_headers_and_sections(fd, &dos, &pe, &sections));

        void *hashes[_UNIFIED_SECTION_MAX] = {};
        size_t hash_size = 0;
        /* No UKI sections to hash — succeeds without hitting the cap path. */
        ASSERT_OK(uki_hash(fd, sym_EVP_sha256(), hashes, &hash_size));
        free_many(hashes, _UNIFIED_SECTION_MAX);
        return EXIT_SUCCESS;
}

#endif  /* HAVE_OPENSSL */

DEFINE_TEST_MAIN(LOG_DEBUG);
