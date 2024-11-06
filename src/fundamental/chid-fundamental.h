/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#if SD_BOOT
#  include "efi-string.h"
#else
#  include <uchar.h>
#endif

#include "efi-fundamental.h"
#include "string-util-fundamental.h"

#define CHID_TYPES_MAX 15

typedef enum ChidSmbiosFields {
        CHID_SMBIOS_MANUFACTURER,
        CHID_SMBIOS_FAMILY,
        CHID_SMBIOS_PRODUCT_NAME,
        CHID_SMBIOS_PRODUCT_SKU,
        CHID_SMBIOS_BASEBOARD_MANUFACTURER,
        CHID_SMBIOS_BASEBOARD_PRODUCT,
        _CHID_SMBIOS_FIELDS_MAX,
} ChidSmbiosFields;

/* CHID (also called HWID by fwupd) is described at https://github.com/fwupd/fwupd/blob/main/docs/hwids.md */
void chid_calculate(const char16_t *const smbios_fields[static _CHID_SMBIOS_FIELDS_MAX], EFI_GUID ret_chids[static CHID_TYPES_MAX]);
