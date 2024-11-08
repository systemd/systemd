/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define FWHEADERMAGIC (UINT32_C(0xfeeddead))

/*  The structure of the efifw UKI blob is the following:
 *  ---------------------------------------------------------
 *  EfiFw header|fwid|payload| reserved for future attributes
 *  ---------------------------------------------------------
 *  The base header defines the length of full header, fwid and payload.
 *  The fwid is a NULL terminated string.
 *  The payload contains the actual efi firmware.
 */
typedef struct EfiFwHeader {
        struct {
                uint32_t magic;
                uint32_t header_len; /* includes base + additional attributes */
                uint32_t fwid_len;
                uint32_t payload_len;
        } base; /* base attributes */
        /* The header might be extended in the future to add additional
         * parameters. header_len will increase to indicate presence of these
         * additional attributes.
         */
} EfiFwHeader;

EFI_STATUS efifirmware_match_by_fwid(const void *uki_efifw, size_t uki_efifw_length, const char *fwid);
