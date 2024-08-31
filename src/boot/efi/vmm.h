/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

bool is_direct_boot(EFI_HANDLE device);
EFI_STATUS vmm_open(EFI_HANDLE *ret_vmm_dev, EFI_FILE **ret_vmm_dir);

bool in_hypervisor(void);

bool is_confidential_vm(void);

const char* smbios_find_oem_string(const char *name);

typedef struct RawSmbiosInfo {
        const char *manufacturer;
        const char *product_mame;
        const char *product_sku;
        const char *family;
        const char *baseboard_product;
        const char *baseboard_manufacturer;
} RawSmbiosInfo;

EFI_STATUS smbios_raw_info_populate(RawSmbiosInfo *info);
