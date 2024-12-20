/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chid-fundamental.h"
#include "string-util.h"
#include "tests.h"

const char16_t *const test_fields[_CHID_SMBIOS_FIELDS_MAX] = {
        [CHID_SMBIOS_MANUFACTURER]           = u"Micro-Star International Co., Ltd.",
        [CHID_SMBIOS_PRODUCT_NAME]           = u"MS-7D70",
        [CHID_SMBIOS_PRODUCT_SKU]            = u"To be filled by O.E.M.",
        [CHID_SMBIOS_FAMILY]                 = u"To be filled by O.E.M.",
        [CHID_SMBIOS_BASEBOARD_PRODUCT]      = u"MPG X670E CARBON WIFI (MS-7D70)",
        [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = u"Micro-Star International Co., Ltd.",
        [CHID_SMBIOS_ENCLOSURE_TYPE]         = u"3",
};

/* Actual output of `fwupdtool hwids`:
BiosVendor: American Megatrends International, LLC.
BiosVersion: 1.E5
BiosMajorRelease: 5
BiosMinorRelease: 32
FirmwareMajorRelease: ff
FirmwareMinorRelease: ff
Manufacturer: Micro-Star International Co., Ltd.
Family: To be filled by O.E.M.
ProductName: MS-7D70
ProductSku: To be filled by O.E.M.
EnclosureKind: 3
BaseboardManufacturer: Micro-Star International Co., Ltd.
BaseboardProduct: MPG X670E CARBON WIFI (MS-7D70)
Hardware IDs
------------
{f59668ca-22bc-52a0-b6b5-1f6ce81b08e0}   <- Manufacturer + Family + ProductName + ProductSku + BiosVendor + BiosVersion + BiosMajorRelease + BiosMinorRelease
{f735f7a0-40da-5bfe-8ac2-0090532ee6d0}   <- Manufacturer + Family + ProductName + BiosVendor + BiosVersion + BiosMajorRelease + BiosMinorRelease
{25880e68-e005-5ca7-88b6-650de596604f}   <- Manufacturer + ProductName + BiosVendor + BiosVersion + BiosMajorRelease + BiosMinorRelease
{01e09b32-de05-56ca-b9d1-9486ad5f381d}   <- Manufacturer + Family + ProductName + ProductSku + BaseboardManufacturer + BaseboardProduct
{cad87a11-1813-507b-9aab-9a5f457b649c}   <- Manufacturer + Family + ProductName + ProductSku
{377c823d-60d1-55b0-9678-76cd2af9d086}   <- Manufacturer + Family + ProductName
{28ac9cf2-5bde-59f7-aebe-4b3d008090fe}   <- Manufacturer + ProductSku + BaseboardManufacturer + BaseboardProduct
{e821e0e2-e11a-5e94-bf5d-ffe53c5e5048}   <- Manufacturer + ProductSku
{1c092f1d-dc7b-564f-8a3d-128d7292fab8}   <- Manufacturer + ProductName + BaseboardManufacturer + BaseboardProduct
{c12c1f4a-332d-5d72-aa36-7a3d413b479a}   <- Manufacturer + ProductName
{28ac9cf2-5bde-59f7-aebe-4b3d008090fe}   <- Manufacturer + Family + BaseboardManufacturer + BaseboardProduct
{e821e0e2-e11a-5e94-bf5d-ffe53c5e5048}   <- Manufacturer + Family
{bdd76d3e-147f-58a9-a0b2-42136454ed07}   <- Manufacturer + EnclosureKind
{b2e58e8b-fb10-5cd0-8fb0-5bd931f1871a}   <- Manufacturer + BaseboardManufacturer + BaseboardProduct
{50af5797-a2f2-58b1-9a1a-453bcbb2e025}   <- Manufacturer
Extra Hardware IDs
------------------
{e6ff1b45-1955-5701-89ab-04fe2280cb4a}   <- Manufacturer + Family + ProductName + ProductSku + BiosVendor
{8c4a76b9-e29e-5a3c-9072-9664898ecae6}   <- Manufacturer + Family + ProductName + BiosVendor
{7b3d90ce-ed79-5951-a48a-764ea9f11146}   <- Manufacturer + BiosVendor
*/

static const EFI_GUID actual_chids[CHID_TYPES_MAX] = {
        {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {0x01e09b32, 0xde05, 0x56ca, {0xb9, 0xd1, 0x94, 0x86, 0xad, 0x5f, 0x38, 0x1d}},
        {0xcad87a11, 0x1813, 0x507b, {0x9a, 0xab, 0x9a, 0x5f, 0x45, 0x7b, 0x64, 0x9c}},
        {0x377c823d, 0x60d1, 0x55b0, {0x96, 0x78, 0x76, 0xcd, 0x2a, 0xf9, 0xd0, 0x86}},
        {0x28ac9cf2, 0x5bde, 0x59f7, {0xae, 0xbe, 0x4b, 0x3d, 0x00, 0x80, 0x90, 0xfe}},
        {0xe821e0e2, 0xe11a, 0x5e94, {0xbf, 0x5d, 0xff, 0xe5, 0x3c, 0x5e, 0x50, 0x48}},
        {0x1c092f1d, 0xdc7b, 0x564f, {0x8a, 0x3d, 0x12, 0x8d, 0x72, 0x92, 0xfa, 0xb8}},
        {0xc12c1f4a, 0x332d, 0x5d72, {0xaa, 0x36, 0x7a, 0x3d, 0x41, 0x3b, 0x47, 0x9a}},
        {0x28ac9cf2, 0x5bde, 0x59f7, {0xae, 0xbe, 0x4b, 0x3d, 0x00, 0x80, 0x90, 0xfe}},
        {0xe821e0e2, 0xe11a, 0x5e94, {0xbf, 0x5d, 0xff, 0xe5, 0x3c, 0x5e, 0x50, 0x48}},
        {0xbdd76d3e, 0x147f, 0x58a9, {0xa0, 0xb2, 0x42, 0x13, 0x64, 0x54, 0xed, 0x07}},
        {0xb2e58e8b, 0xfb10, 0x5cd0, {0x8f, 0xb0, 0x5b, 0xd9, 0x31, 0xf1, 0x87, 0x1a}},
        {0x50af5797, 0xa2f2, 0x58b1, {0x9a, 0x1a, 0x45, 0x3b, 0xcb, 0xb2, 0xe0, 0x25}},
};

TEST(chid) {
        /* Results compared with output of 'fwupdtool hwids' */
        EFI_GUID chids[CHID_TYPES_MAX];
        chid_calculate(test_fields, chids);
        for (size_t i = 0; i < ELEMENTSOF(chids); i++)
                ASSERT_EQ_EFI_GUID(&chids[i], &actual_chids[i]);
}

static int intro(void) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return EXIT_SUCCESS;
#else
        return log_tests_skipped("cannot run CHID calculation on big-endian machine");
#endif
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
