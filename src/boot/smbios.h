/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

bool smbios_in_hypervisor(void);

const char* smbios_find_oem_string(const char *name);

typedef struct RawSmbiosInfo {
        const char *manufacturer;
        const char *product_name;
        const char *product_sku;
        const char *family;
        const char *baseboard_product;
        const char *baseboard_manufacturer;
} RawSmbiosInfo;

void smbios_raw_info_populate(RawSmbiosInfo *ret_info);
void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info);
