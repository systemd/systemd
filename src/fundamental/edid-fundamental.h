/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if SD_BOOT
#  include "efi-string.h"
#  include "util.h"
#else
#  include <stddef.h>
#  include <stdint.h>
#  include <uchar.h>
#endif

#include "macro-fundamental.h"

/* EDID structure, version 1.4 */
typedef struct EdidHeader {
        uint8_t pattern[8];                   /* fixed pattern */
        uint16_t manufacturer_id;             /* big-endian 3-letter code */
        uint16_t manufacturer_product_code;   /* little-endian */
        uint32_t serial_number;               /* little-endian */
        uint8_t week_of_manufacture;          /* week or model year flag (0xFF) */
        uint8_t year_of_manufacture;          /* year or model if flag is set (0 is 1990) */
        uint8_t edid_version;                 /* 0x01 for 1.3 and 1.4 */
        uint8_t edid_revision;                /* 0x03 for 1.3, 0x04 for 1.4 */
} _packed_ EdidHeader;

int edid_parse_blob(const void *blob, size_t blob_size, EdidHeader *ret_header);
int edid_get_panel_id(const EdidHeader *edid_header, char16_t ret_panel[static 8]);
