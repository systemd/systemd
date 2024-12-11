/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include <stddef.h>
#include <stdint.h>

#include "efi.h"
#include "chid.h"
#include "chid-match-util.h"

#include "tests.h"

extern uint8_t hwids_section_data[];
extern size_t hwids_section_len;

static const RawSmbiosInfo smbios_info[] = {
        {
                .manufacturer           = "First Vendor",
                .product_name           = "Device 1",
                .product_sku            = "KD01",
                .family                 = "Laptop X",
                .baseboard_product      = "FODM1",
                .baseboard_manufacturer = "First ODM",
        },
        {
                .manufacturer           = "Second Vendor",
                .product_name           = "Device 2",
                .product_sku            = "KD02",
                .family                 = "Laptop 2",
                .baseboard_product      = "SODM2",
                .baseboard_manufacturer = "Second ODM",
        },
        {
                .manufacturer           = "First Vendor",
                .product_name           = "Device 3",
                .product_sku            = "KD03",
                .family                 = "Tablet Y",
                .baseboard_product      = "FODM2",
                .baseboard_manufacturer = "First ODM",
        },
};

static struct {
        const char *name;
        const char *compatible;
} results[] = {
        { "Device 1", "test,device-1" },
        { "Device 2", "test,device-2" },
        { "Device 3", "test,device-3" },
};

TEST(chid) {
        for (size_t i = 0; i < ELEMENTSOF(smbios_info); i++) {
                /* Reset cached SMBIOS strings and update for the current test */
                chid_match_reset_cache();
                chid_match_set_raw(smbios_info[i]);
                const Device *dev = NULL;
                /* Match and check */
                ASSERT_EQ(chid_match(hwids_section_data, hwids_section_len, &dev), EFI_SUCCESS);
                ASSERT_NOT_NULL(dev);
                ASSERT_STREQ(device_get_name(hwids_section_data, dev), results[i].name);
                ASSERT_STREQ(device_get_compatible(hwids_section_data, dev), results[i].compatible);
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
