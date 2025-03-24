/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "edid.h"
#include "log.h"
#include "proto/edid-discovered.h"
#include "util.h"

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
} EdidHeader;

static const uint8_t header_pattern[] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

EFI_STATUS edid_get_panel_id(char16_t **ret_panel) {
        EFI_STATUS status = EFI_SUCCESS;
        EFI_EDID_DISCOVERED_PROTOCOL *edid_discovered = NULL;

        status = BS->LocateProtocol(MAKE_GUID_PTR(EFI_EDID_DISCOVERED_PROTOCOL), NULL, (void **) &edid_discovered);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        if (!edid_discovered)
                return EFI_UNSUPPORTED;
        if (!edid_discovered->Edid)
                return EFI_UNSUPPORTED;
        if (edid_discovered->SizeOfEdid == 0)
                return EFI_UNSUPPORTED;

        if (edid_discovered->SizeOfEdid < 128)
                return EFI_BUFFER_TOO_SMALL;

        const EdidHeader *edid_header = (const EdidHeader *) edid_discovered->Edid;

        if (memcmp(edid_header->pattern, header_pattern, sizeof(header_pattern)) != 0)
                return EFI_INCOMPATIBLE_VERSION;

        uint16_t manufacturer_id = bswap_16(edid_header->manufacturer_id);

        /* 3-letter Manufacturer ID + 16-bit product code */
        char16_t *panel_id = xnew0(char16_t, 5);

        for (size_t i = 0; i < 3; i++) {
                uint8_t letter = (manufacturer_id >> (5 * i)) & 0b11111;
                if (letter <= 0b11010)
                        panel_id[2 - i] = letter + 'A' - 1;
                else
                        log_error("Invalid letter: 0x%x", letter);
        }

#ifdef EFI_DEBUG
        log_info("Panel manufacturer: %ls (0x%x), product: 0x%x", panel_id, manufacturer_id, edid_header->manufacturer_product_code);
#endif

        panel_id[3] = edid_header->manufacturer_product_code;
        *ret_panel = panel_id;

        return EFI_SUCCESS;
}
