/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define FWHEADERMAGIC 0xfeeddead

/* The structure of the efifw UKI blob is the following:
 *  ----------------------------------
 *  EfiFw header|metadata|fwid|payload
 *  ----------------------------------
 *  The header defines the length of metadata, fwid and payload.
 *  The fwid is a NULL terminated string.
 *  The payload contains the actual efi firmware.
 */
typedef struct EfiFwHeader {
        uint32_t magic;
        uint32_t total_size; /* includes header, fwid and payload */
        uint32_t fw_metadata_offset;
        uint32_t fw_metadata_len;
        uint32_t fwid_offset;
        uint32_t fwid_len;
        uint32_t payload_offset;
        uint32_t payload_len;
} EfiFwHeader;

EFI_STATUS efifirmware_match_by_fwid(const void *uki_efifw, size_t uki_efifw_length, const char *fwid);
