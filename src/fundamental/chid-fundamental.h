/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#if SD_BOOT
#  include "efi.h"
#else
#  include <uchar.h>
#endif

#include "efi-fundamental.h"

#define CHID_TYPES_MAX 18
/* Any chids starting from EXTRA_CHID_BASE are non-standard and are subject to change and renumeration at any time */
#define EXTRA_CHID_BASE 15

typedef enum ChidSmbiosFields {
        CHID_SMBIOS_MANUFACTURER,
        CHID_SMBIOS_FAMILY,
        CHID_SMBIOS_PRODUCT_NAME,
        CHID_SMBIOS_PRODUCT_SKU,
        CHID_SMBIOS_BASEBOARD_MANUFACTURER,
        CHID_SMBIOS_BASEBOARD_PRODUCT,
        CHID_SMBIOS_BIOS_VENDOR,
        CHID_SMBIOS_BIOS_VERSION,
        CHID_SMBIOS_BIOS_MAJOR,
        CHID_SMBIOS_BIOS_MINOR,
        CHID_SMBIOS_ENCLOSURE_TYPE,
        CHID_EDID_PANEL,
        _CHID_SMBIOS_FIELDS_MAX,
} ChidSmbiosFields;

extern const uint32_t chid_smbios_table[CHID_TYPES_MAX];

/* CHID (also called HWID by fwupd) is described at https://github.com/fwupd/fwupd/blob/main/docs/hwids.md */
void chid_calculate(const char16_t *const smbios_fields[static _CHID_SMBIOS_FIELDS_MAX], EFI_GUID ret_chids[static CHID_TYPES_MAX]);
