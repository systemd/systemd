/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define SMBIOS_TABLE_GUID \
        GUID_DEF(0xeb9d2d31, 0x2d88, 0x11d3, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)
#define SMBIOS3_TABLE_GUID \
        GUID_DEF(0xf2fd1544, 0x9794, 0x4a2c, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94)

typedef struct {
        uint8_t anchor_string[4];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint16_t max_structure_size;
        uint8_t entry_point_revision;
        uint8_t formatted_area[5];
        uint8_t intermediate_anchor_string[5];
        uint8_t intermediate_checksum;
        uint16_t table_length;
        uint32_t table_address;
        uint16_t number_of_smbios_structures;
        uint8_t smbios_bcd_revision;
} _packed_ SmbiosEntryPoint;

typedef struct {
        uint8_t anchor_string[5];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint8_t docrev;
        uint8_t entry_point_revision;
        uint8_t reserved;
        uint32_t table_maximum_size;
        uint64_t table_address;
} _packed_ Smbios3EntryPoint;

typedef struct {
        uint8_t type;
        uint8_t length;
        uint8_t handle[2];
} _packed_ SmbiosHeader;

typedef struct {
        SmbiosHeader header;
        uint8_t vendor;
        uint8_t bios_version;
        uint16_t bios_segment;
        uint8_t bios_release_date;
        uint8_t bios_size;
        uint64_t bios_characteristics;
        uint8_t bios_characteristics_ext[2];
} _packed_ SmbiosTableType0;

typedef struct {
        SmbiosHeader header;
        uint8_t manufacturer;
        uint8_t product_name;
        uint8_t version;
        uint8_t serial_number;
        uint8_t uuid[16];
        uint8_t wake_up_type;
        uint8_t sku_number;
        uint8_t family;
        char strings[];
} _packed_ SmbiosTableType1;

typedef struct {
        SmbiosHeader header;
        uint8_t count;
        char contents[];
} _packed_ SmbiosTableType11;

const void *find_smbios_configuration_table(uint64_t *ret_size);

const SmbiosHeader *get_smbios_table(uint8_t type, uint64_t *ret_size_left);

bool smbios_in_hypervisor(void);

const char* smbios_find_oem_string(const char *name);

const char* smbios_system_product_name(void);
