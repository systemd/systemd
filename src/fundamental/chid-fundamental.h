/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include "string-util-fundamental.h"

typedef enum ChidSmbiosFields {
        CHID_SMBIOS_MANUFACTURER,
        CHID_SMBIOS_FAMILY,
        CHID_SMBIOS_PRODUCT_NAME,
        CHID_SMBIOS_PRODUCT_SKU,
        CHID_SMBIOS_BASEBOARD_MANUFACTURER,
        CHID_SMBIOS_BASEBOARD_PRODUCT,
        CHID_SMBIOS_COUNT,
} ChidSmbiosFields;

typedef struct SmbiosInfo {
        char16_t *str[CHID_SMBIOS_COUNT];
} SmbiosInfo;

typedef struct Uuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} Uuid;

/* HWID is described at https://github.com/fwupd/fwupd/blob/main/docs/hwids.md */
void hwid_calculate(SmbiosInfo *info, Uuid ret_hwids[static 15]);
