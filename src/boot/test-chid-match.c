/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <stdint.h>

#include "chid.h"
#include "smbios.h"
#include "tests.h"

extern uint8_t hwids_section_data[];
extern size_t hwids_section_len;

static struct {
        const RawSmbiosInfo smbios_info;
        uint32_t device_type;
} info[] = {
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
        },
        {
                .smbios_info = {
                        .manufacturer           = "VMware, Inc.",
                        .product_name           = "VMware20,1",
                        .product_sku            = "0000000000000001",
                        .family                 = "VMware",
                        .baseboard_product      = "VBSA",
                        .baseboard_manufacturer = "VMware, Inc.",
                },
                .device_type = DEVICE_TYPE_UEFI_FW,
        },
};

static struct {
        const char *name;
        const char *compatible;
        const char *fwid;
} results[] = {
        { "Device 1", "test,device-1", NULL },
        { "Device 2", "test,device-2", NULL },
        { "Device 3", "test,device-3", NULL },
        { "Device 4", NULL, "test,vmware" },
};

static RawSmbiosInfo current_info = {};

/* This is a dummy implementation for testing purposes */
void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info) {
        assert(ret_info);
        *ret_info = current_info;
}

TEST(chid_match) {
        for (size_t i = 0; i < ELEMENTSOF(info); i++) {
                current_info = info[i].smbios_info;
                const Device *dev = NULL;
                /* Match and check */
                ASSERT_EQ(chid_match(hwids_section_data, hwids_section_len, info[i].device_type, &dev), EFI_SUCCESS);
                ASSERT_NOT_NULL(dev);
                ASSERT_EQ(DEVICE_TYPE_FROM_DESCRIPTOR(dev->descriptor), info[i].device_type);
                ASSERT_STREQ(device_get_name(hwids_section_data, dev), results[i].name);
                ASSERT_STREQ(device_get_compatible(hwids_section_data, dev), results[i].compatible);
                ASSERT_STREQ(device_get_fwid(hwids_section_data, dev), results[i].fwid);
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
