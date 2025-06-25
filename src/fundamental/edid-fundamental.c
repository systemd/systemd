/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !SD_BOOT
#include <endian.h>
#endif

#include "edid-fundamental.h"
#include "efivars-fundamental.h"

#define EDID_FIXED_HEADER_PATTERN "\x00\xFF\xFF\xFF\xFF\xFF\xFF"
assert_cc(sizeof_field(EdidHeader, pattern) == sizeof(EDID_FIXED_HEADER_PATTERN));

int edid_parse_blob(const void *blob, size_t blob_size, EdidHeader *ret_header) {
        assert(ret_header);

        /* EDID size is at least 128 as per the specification */
        if (blob_size < 128)
                return -EINVAL;

        const EdidHeader *edid_header = ASSERT_PTR(blob);
        if (memcmp(edid_header->pattern, EDID_FIXED_HEADER_PATTERN, sizeof(EDID_FIXED_HEADER_PATTERN)) != 0)
                return -EINVAL;

        *ret_header = (EdidHeader) {
                .pattern = EDID_FIXED_HEADER_PATTERN,
                .manufacturer_id = be16toh(edid_header->manufacturer_id),
                .manufacturer_product_code = le16toh(edid_header->manufacturer_product_code),
                .serial_number = le32toh(edid_header->serial_number),
                .week_of_manufacture = edid_header->week_of_manufacture,
                .year_of_manufacture = edid_header->year_of_manufacture,
                .edid_version = edid_header->edid_version,
                .edid_revision = edid_header->edid_revision,
        };
        return 0;
}

int edid_get_panel_id(const EdidHeader *edid_header, char16_t ret_panel[static 8]) {
        assert(edid_header);
        assert(ret_panel);

        for (size_t i = 0; i < 3; i++) {
                uint8_t letter = (edid_header->manufacturer_id >> (5 * i)) & 0b11111;
                if (letter > 0b11010)
                        return -EINVAL;
                ret_panel[2 - i] = letter + 'A' - 1;
        }
        ret_panel[3] = LOWERCASE_HEXDIGITS[(edid_header->manufacturer_product_code >> 12) & 0x0F];
        ret_panel[4] = LOWERCASE_HEXDIGITS[(edid_header->manufacturer_product_code >>  8) & 0x0F];
        ret_panel[5] = LOWERCASE_HEXDIGITS[(edid_header->manufacturer_product_code >>  4) & 0x0F];
        ret_panel[6] = LOWERCASE_HEXDIGITS[(edid_header->manufacturer_product_code >>  0) & 0x0F];
        ret_panel[7] = L'\0';
        return 0;
}
