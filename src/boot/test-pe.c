/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <stdint.h>

#include "chid.h"
#include "devicetree.h"
#include "pe.h"
#include "smbios.h"
#include "tests.h"
#include "uki.h"

extern uint8_t _binary_src_boot_pe_efi_start[];
extern size_t _binary_src_boot_pe_efi_size;

static struct {
        const RawSmbiosInfo smbios_info;
        uint32_t device_type;
        const char *compatible;
        const char *fwid;
} tests[] = {
        {
                .smbios_info =  {
                        .manufacturer           = "First Vendor",
                        .product_name           = "Device 1",
                        .product_sku            = "KD01",
                        .family                 = "Laptop X",
                        .baseboard_product      = "FODM1",
                        .baseboard_manufacturer = "First ODM",
                },
                .device_type = DEVICE_TYPE_DEVICETREE,
                .compatible = "test,device-1",
        },
        {
                .smbios_info = {
                        .manufacturer           = "Second Vendor",
                        .product_name           = "Device 2",
                        .product_sku            = "KD02",
                        .family                 = "Laptop 2",
                        .baseboard_product      = "SODM2",
                        .baseboard_manufacturer = "Second ODM",
                },
                .device_type = DEVICE_TYPE_DEVICETREE,
                .compatible = "test,device-2",
        },
        {
                .smbios_info = {
                        .manufacturer           = "First Vendor",
                        .product_name           = "Device 3",
                        .product_sku            = "KD03",
                        .family                 = "Tablet Y",
                        .baseboard_product      = "FODM2",
                        .baseboard_manufacturer = "First ODM",
                },
                .device_type = DEVICE_TYPE_DEVICETREE,
                .compatible = "test,device-3",
        },
};

static RawSmbiosInfo current_info = {};

/* This is a dummy implementation for testing purposes */
void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info) {
        assert(ret_info);
        *ret_info = current_info;
}

TEST(pe_memory_locate) {
        FOREACH_ELEMENT(test, tests) {
                current_info = test->smbios_info;
                PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
                /* Locate and check */
                ASSERT_EQ(pe_memory_locate_sections(_binary_src_boot_pe_efi_start, unified_sections, sections), EFI_SUCCESS);
                ASSERT_TRUE(PE_SECTION_VECTOR_IS_SET(&sections[UNIFIED_SECTION_LINUX]));
                const uint8_t *kernel = _binary_src_boot_pe_efi_start + sections[UNIFIED_SECTION_LINUX].file_offset;
                ASSERT_EQ(memcmp(kernel, "MZ\0\0", 4), 0);
                const char *cmdline = PE_SECTION_DATA_FROM_VECTOR(_binary_src_boot_pe_efi_start, &sections[UNIFIED_SECTION_CMDLINE]);
                ASSERT_STREQ(cmdline, "test");
                const char *osrel = PE_SECTION_DATA_FROM_VECTOR(_binary_src_boot_pe_efi_start, &sections[UNIFIED_SECTION_OSREL]);
                ASSERT_STREQ(osrel, "v7");

                if (PE_SECTION_VECTOR_IS_SET(&sections[UNIFIED_SECTION_DTBAUTO])) {
                        const uint8_t *dtb = _binary_src_boot_pe_efi_start + sections[UNIFIED_SECTION_DTBAUTO].file_offset;
                        const size_t dtb_length = sections[UNIFIED_SECTION_DTBAUTO].file_size;
                        ASSERT_EQ(devicetree_match_by_compatible(dtb, dtb_length, test->compatible), EFI_SUCCESS);
                }
        }
}

static int intro(void) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return EXIT_SUCCESS;
#else
        return log_tests_skipped("cannot run CHID calculation on big-endian machine");
#endif
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
