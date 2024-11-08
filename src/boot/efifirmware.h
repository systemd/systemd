/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define FWHEADERMAGIC (UINT32_C(0xfeeddead))

/*  The structure of the efifw UKI blob is the following:
 *  ---------------------------------------------------------
 *  EfiFw header|fwid|payload| reserved for future attributes
 *  ---------------------------------------------------------
 *  The base header defines the length of full header, fwid and payload.
 *  The fwid is a NUL terminated string.
 *  The payload contains the actual efi firmware.
 */
typedef struct EfiFwHeader {
        uint32_t magic; /* magic number that defines Efifw */
        uint32_t header_len; /* total length of header including all attributes */
        uint32_t fwid_len; /* length including the NUL terminator */
        uint32_t payload_len; /* actual length of the efi firmware binary image */

        /* The header might be extended in the future to add additional
         * parameters. header_len will increase to indicate presence of these
         * additional attributes.
         */

        /* next comes payload which is fwid and efi firmware binary blob */
        uint8_t payload[] _alignas_(uint64_t);
} EfiFwHeader;

EFI_STATUS efifirmware_match_by_fwid(const void *uki_efifw, size_t uki_efifw_length, const char *fwid);
