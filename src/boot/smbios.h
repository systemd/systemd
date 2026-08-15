/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

typedef struct {
        uint8_t type;
        uint8_t length;
        uint8_t handle[2];
} _packed_ SmbiosHeader;

typedef struct {
        SmbiosHeader header;
        uint8_t manufacturer;
        uint8_t product_name;
        uint8_t version;
        uint8_t serial_number;
        EFI_GUID uuid;
        uint8_t wake_up_type;
        uint8_t sku_number;
        uint8_t family;
} _packed_ SmbiosTableType1;

bool smbios_in_hypervisor(void);

const char* smbios_find_oem_string(const char *name, const char *after);

/* Invoked by smbios_foreach() for each SMBIOS structure. 'header' points at the structure (which
 * carries its type), and 'size' is the structure's total length (formatted area + trailing string
 * set). Returning false stops the iteration. */
typedef bool (*SmbiosForeachFunc)(const SmbiosHeader *header, size_t size, void *userdata);

void smbios_foreach(SmbiosForeachFunc func, void *userdata);

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
