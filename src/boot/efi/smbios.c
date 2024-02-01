/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "smbios.h"
#include "util.h"

const void *find_smbios_configuration_table(uint64_t *ret_size) {
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

        return NULL;
}

const SmbiosHeader *get_smbios_table(uint8_t type, uint64_t *ret_size_left) {
        uint64_t size = 0;
        const uint8_t *p = find_smbios_configuration_table(&size);
        if (!p)
                return NULL;

        for (;;) {
                if (size < sizeof(SmbiosHeader))
                        return NULL;

                const SmbiosHeader *header = (const SmbiosHeader *) p;

                /* End of table. */
                if (header->type == 127)
                        return NULL;

                if (size < header->length)
                        return NULL;

                if (header->type == type) {
                        if (ret_size_left)
                                *ret_size_left = size;
                        return header; /* Yay! */
                }

                /* Skip over formatted area. */
                size -= header->length;
                p += header->length;

                /* Skip chars until a double NUL */
                while (!(p[0] == '\0' && p[1] == '\0')) {
                        p += 1;
                        size -= 1;
                }

                /* Skip double NUL */
                p += 2;
                size -= 2;
        }

        return NULL;
}

bool smbios_in_hypervisor(void) {
        /* Look up BIOS Information (Type 0). */
        const SmbiosTableType0 *type0 = (const SmbiosTableType0 *) get_smbios_table(0, NULL);
        if (!type0 || type0->header.length < sizeof(SmbiosTableType0))
                return false;

        /* Bit 4 of 2nd BIOS characteristics extension bytes indicates virtualization. */
        return FLAGS_SET(type0->bios_characteristics_ext[1], 1 << 4);
}

const char* smbios_find_oem_string(const char *name) {
        assert(name);

        uint64_t left;
        const SmbiosTableType11 *type11 = (const SmbiosTableType11 *) get_smbios_table(11, &left);
        if (!type11 || type11->header.length < sizeof(SmbiosTableType11))
                return NULL;

        assert(left >= type11->header.length);

        const char *s = type11->contents;
        left -= type11->header.length;

        for (const char *p = s; p < s + left; ) {

                // Found double NUL
                if (p[0] == '\0' && p[1] == '\0') {
                        p += 2;
                        break;
                }

                // Find end of string (should always exist, every string is NUL terminated)
                const char *e = ASSERT_PTR(memchr(p, 0, s + left - p));

                const char *eq = startswith8(p, name);
                if (eq && *eq == '=')
                        return eq + 1;

                p = e + 1;
        }

        return NULL;
}

const char* smbios_system_product_name(void) {
        uint64_t left;
        const SmbiosTableType1 *type1 = (const SmbiosTableType1 *) get_smbios_table(1, &left);
        if (!type1 || type1->header.length < offsetof(SmbiosTableType1, product_name) + 1)
                return NULL;

        size_t str_idx = 1;     /* NOTE: SMBIOS strings are indexed base-1 */
        const char *s = type1->strings;
        left -= type1->header.length;

        for (const char *p = s; p < s + left; ) {
                // Found double NUL
                if (p[0] == '\0' && p[1] == '\0') {
                        p += 2;
                        break;
                }

                // Find end of string (should always exist, every string is NUL terminated)
                const char *e = ASSERT_PTR(memchr(p, 0, s + left - p));

                if (str_idx == type1->product_name)
                        return p;

                p = e + 1;
                str_idx += 1;
        }

        return NULL;
}
