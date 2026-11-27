/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe-reloc.h"
#include "tests.h"
#include "unaligned.h"

#define IMAGE_REL_BASED_HIGHLOW 3

#define TEST_IMAGE_SIZE 0x800U
#define TEST_RELOC_RVA  0x200U
#define TEST_TEXT_RVA   0x400U
#define TEST_RELOC_SIZE 12U

static void make_test_image(
                uint8_t image[static TEST_IMAGE_SIZE],
                uint64_t fixup_value,
                uint32_t page_rva,
                uint16_t entry) {

        unaligned_write_ne32(image + TEST_RELOC_RVA, page_rva);
        unaligned_write_ne32(image + TEST_RELOC_RVA + 4, TEST_RELOC_SIZE);
        unaligned_write_ne16(image + TEST_RELOC_RVA + 8, entry);
        unaligned_write_ne16(image + TEST_RELOC_RVA + 10, IMAGE_REL_BASED_ABSOLUTE << 12);

        uint32_t fixup_rva = page_rva + (entry & 0x0FFF);
        if (fixup_rva <= TEST_IMAGE_SIZE && sizeof(uint64_t) <= TEST_IMAGE_SIZE - fixup_rva)
                unaligned_write_ne64(image + fixup_rva, fixup_value);
}

TEST(pe_apply_base_relocations_add) {
        const uint64_t image_base = UINT64_C(0x100000);
        const uint64_t actual_base = UINT64_C(0x105000);
        const uint64_t fixup_value = image_base + UINT64_C(0x2340);
        uint8_t image[TEST_IMAGE_SIZE] = {};

        make_test_image(image, fixup_value, TEST_TEXT_RVA, (IMAGE_REL_BASED_DIR64 << 12) | 0x20);

        ASSERT_EQ(pe_apply_base_relocations(
                          image, sizeof(image), TEST_RELOC_RVA, TEST_RELOC_SIZE, actual_base - image_base),
                  EFI_SUCCESS);
        ASSERT_EQ(unaligned_read_ne64(image + TEST_TEXT_RVA + 0x20), fixup_value + (actual_base - image_base));
}

TEST(pe_apply_base_relocations_subtract) {
        const uint64_t image_base = UINT64_C(0x200000);
        const uint64_t actual_base = UINT64_C(0x1ff000);
        const uint64_t fixup_value = image_base + UINT64_C(0x5000);
        uint8_t image[TEST_IMAGE_SIZE] = {};

        make_test_image(image, fixup_value, TEST_TEXT_RVA, (IMAGE_REL_BASED_DIR64 << 12) | 0x20);

        ASSERT_EQ(pe_apply_base_relocations(
                          image, sizeof(image), TEST_RELOC_RVA, TEST_RELOC_SIZE, actual_base - image_base),
                  EFI_SUCCESS);
        ASSERT_EQ(unaligned_read_ne64(image + TEST_TEXT_RVA + 0x20), fixup_value + (actual_base - image_base));
}

TEST(pe_apply_base_relocations_zero_delta) {
        const uint64_t fixup_value = UINT64_C(0x205000);
        uint8_t image[TEST_IMAGE_SIZE] = {};

        /* An unsupported entry proves that a zero delta skips the relocation walk. */
        make_test_image(image, fixup_value, TEST_TEXT_RVA, (IMAGE_REL_BASED_HIGHLOW << 12) | 0x20);

        ASSERT_EQ(pe_apply_base_relocations(image, sizeof(image), TEST_RELOC_RVA, TEST_RELOC_SIZE, 0), EFI_SUCCESS);
        ASSERT_EQ(unaligned_read_ne64(image + TEST_TEXT_RVA + 0x20), fixup_value);
}

TEST(pe_apply_base_relocations_unsupported_type) {
        uint8_t image[TEST_IMAGE_SIZE] = {};

        make_test_image(image, UINT64_C(0x305000), TEST_TEXT_RVA, (IMAGE_REL_BASED_HIGHLOW << 12) | 0x20);

        ASSERT_EQ(pe_apply_base_relocations(image, sizeof(image), TEST_RELOC_RVA, TEST_RELOC_SIZE, 0x1000), EFI_LOAD_ERROR);
}

TEST(pe_apply_base_relocations_truncated_block) {
        uint8_t image[TEST_IMAGE_SIZE] = {};

        ASSERT_EQ(pe_apply_base_relocations(image, sizeof(image), TEST_RELOC_RVA, 7, 0x1000), EFI_LOAD_ERROR);
}

TEST(pe_apply_base_relocations_table_outside_image) {
        uint8_t image[TEST_IMAGE_SIZE] = {};

        ASSERT_EQ(pe_apply_base_relocations(image, sizeof(image), TEST_IMAGE_SIZE - 4, 8, 0x1000), EFI_LOAD_ERROR);
}

TEST(pe_apply_base_relocations_fixup_overflow) {
        /* Adding the entry offset would wrap the fixup RVA to .text, inside the image. */
        const uint32_t page_rva = UINT32_MAX - 0x0FFF + TEST_TEXT_RVA + 1;
        uint8_t image[TEST_IMAGE_SIZE] = {};

        make_test_image(image, UINT64_C(0x300000), page_rva, (IMAGE_REL_BASED_DIR64 << 12) | 0x0FFF);

        ASSERT_EQ(pe_apply_base_relocations(image, sizeof(image), TEST_RELOC_RVA, TEST_RELOC_SIZE, 0x1000), EFI_LOAD_ERROR);
}

DEFINE_TEST_MAIN(LOG_INFO);
