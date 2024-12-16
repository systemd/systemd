/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "efivars.h"
#include "proto/device-path.h"
#include "smbios.h"
#include "string-util-fundamental.h"
#include "util.h"

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
        EFI_GUID uuid;
        uint8_t wake_up_type;
        uint8_t sku_number;
        uint8_t family;
} _packed_ SmbiosTableType1;

typedef struct {
        SmbiosHeader header;
        uint8_t manufacturer;
        uint8_t product_name;
        uint8_t version;
        uint8_t serial_number;
} _packed_ SmbiosTableType2;

typedef struct {
        SmbiosHeader header;
        uint8_t count;
        char contents[];
} _packed_ SmbiosTableType11;

static const void* find_smbios_configuration_table(uint64_t *ret_size) {
        assert(ret_size);

        const Smbios3EntryPoint *entry3 = find_configuration_table(MAKE_GUID_PTR(SMBIOS3_TABLE));
        if (entry3 && memcmp(entry3->anchor_string, "_SM3_", 5) == 0 &&
            entry3->entry_point_length <= sizeof(*entry3)) {
                *ret_size = entry3->table_maximum_size;
                return PHYSICAL_ADDRESS_TO_POINTER(entry3->table_address);
        }

        const SmbiosEntryPoint *entry = find_configuration_table(MAKE_GUID_PTR(SMBIOS_TABLE));
        if (entry && memcmp(entry->anchor_string, "_SM_", 4) == 0 &&
            entry->entry_point_length <= sizeof(*entry)) {
                *ret_size = entry->table_length;
                return PHYSICAL_ADDRESS_TO_POINTER(entry->table_address);
        }

        *ret_size = 0;
        return NULL;
}

static const SmbiosHeader* get_smbios_table(uint8_t type, size_t min_size, uint64_t *ret_size_left) {
        uint64_t size;
        const uint8_t *p = find_smbios_configuration_table(&size);
        if (!p)
                goto not_found;

        for (;;) {
                if (size < sizeof(SmbiosHeader))
                        goto not_found;

                const SmbiosHeader *header = (const SmbiosHeader *) p;

                /* End of table. */
                if (header->type == 127)
                        goto not_found;

                if (size < header->length)
                        goto not_found;

                if (header->type == type) {
                        /* Table is smaller than the minimum expected size? Refuse */
                        if (header->length < min_size)
                                goto not_found;

                        if (ret_size_left)
                                *ret_size_left = size;
                        return header; /* Yay! */
                }

                /* Skip over formatted area. */
                size -= header->length;
                p += header->length;

                /* Special case: if there are no strings appended, we'll see two NUL bytes, skip over them */
                if (size >= 2 && p[0] == 0 && p[1] == 0) {
                        size -= 2;
                        p += 2;
                        continue;
                }

                /* Skip over a populated string table. */
                bool first = true;
                for (;;) {
                        const uint8_t *e = memchr(p, 0, size);
                        if (!e)
                                goto not_found;

                        if (!first && e == p) {/* Double NUL byte means we've reached the end of the string table. */
                                p++;
                                size--;
                                break;
                        }

                        size -= e + 1 - p;
                        p = e + 1;
                        first = false;
                }
        }

not_found:
        if (ret_size_left)
                *ret_size_left = 0;

        return NULL;
}

bool smbios_in_hypervisor(void) {
        /* Look up BIOS Information (Type 0). */
        const SmbiosTableType0 *type0 = (const SmbiosTableType0 *) get_smbios_table(0, sizeof(SmbiosTableType0), /* left= */ NULL);
        if (!type0)
                return false;

        /* Bit 4 of 2nd BIOS characteristics extension bytes indicates virtualization. */
        return FLAGS_SET(type0->bios_characteristics_ext[1], 1 << 4);
}

const char* smbios_find_oem_string(const char *name) {
        uint64_t left;

        assert(name);

        const SmbiosTableType11 *type11 = (const SmbiosTableType11 *) get_smbios_table(11, sizeof(SmbiosTableType11), &left);
        if (!type11)
                return NULL;

        assert(left >= type11->header.length); /* get_smbios_table() already validated this */
        left -= type11->header.length;

        for (const char *p = type11->contents, *limit = type11->contents + left; p < limit; ) {
                const char *e = memchr(p, 0, limit - p);
                if (!e || e == p) /* Double NUL byte means we've reached the end of the OEM strings. */
                        break;

                const char *eq = startswith8(p, name);
                if (eq && *eq == '=')
                        return eq + 1;

                p = e + 1;
        }

        return NULL;
}

static const char* smbios_get_string(const SmbiosHeader *header, size_t nr, uint64_t left) {
        const char *s = (const char *) ASSERT_PTR(header);

        /* We assume that get_smbios_table() already validated the header size making some superficial sense */
        assert(left >= header->length);
        s += header->length;
        left -= header->length;

        size_t index = 1;
        for (const char *p = s, *limit = s + left; index <= nr && p < limit; index++) {
                const char *e = memchr(p, 0, limit - p);
                if (!e || e == p) /* Double NUL byte means we've reached the end of the strings. */
                        break;

                if (index == nr)
                        return p;

                p = e + 1;
        }

        return NULL;
}

void smbios_raw_info_populate(RawSmbiosInfo *ret_info) {
        uint64_t left;

        assert(ret_info);

        const SmbiosTableType1 *type1 = (const SmbiosTableType1 *) get_smbios_table(1, sizeof(SmbiosTableType1), &left);
        if (type1) {
                ret_info->manufacturer = smbios_get_string(&type1->header, type1->manufacturer, left);
                ret_info->product_name = smbios_get_string(&type1->header, type1->product_name, left);
                ret_info->product_sku = smbios_get_string(&type1->header, type1->sku_number, left);
                ret_info->family = smbios_get_string(&type1->header, type1->family, left);
        } else {
                ret_info->manufacturer = NULL;
                ret_info->product_name = NULL;
                ret_info->product_sku = NULL;
                ret_info->family = NULL;
        }

        const SmbiosTableType2 *type2 = (const SmbiosTableType2 *) get_smbios_table(2, sizeof(SmbiosTableType2), &left);
        if (type2) {
                ret_info->baseboard_manufacturer = smbios_get_string(&type2->header, type2->manufacturer, left);
                ret_info->baseboard_product = smbios_get_string(&type2->header, type2->product_name, left);
        } else {
                ret_info->baseboard_manufacturer = NULL;
                ret_info->baseboard_product = NULL;
        }
}

void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info) {
        static RawSmbiosInfo info = {};
        static bool cached = false;

        assert(ret_info);

        if (!cached) {
                smbios_raw_info_populate(&info);
                cached = true;
        }

        *ret_info = info;
}
