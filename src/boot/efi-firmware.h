/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define FWHEADERMAGIC (UINT32_C(0xfeeddead))

/* The structure of the efifw UKI blob is the following:
 * ---------------------------------------------------------
 * EfiFw header|fwid|payload| reserved for future attributes
 * ---------------------------------------------------------
 * The base header defines the length of full header, fwid and payload.
 * The fwid is a NUL terminated string.
 * The payload contains the actual efi firmware. */
typedef struct EfiFwHeader {
        uint32_t magic; /* magic number that defines Efifw */
        uint32_t header_len; /* total length of header including all attributes */
        uint32_t fwid_len; /* length including the NUL terminator */
        uint32_t payload_len; /* actual length of the efi firmware binary image */

        /* The header might be extended in the future to add additional
         * parameters. header_len will increase to indicate presence of these
         * additional attributes.
         */

        EFI_GUID chid; /* (optional) When non-zero, the payload is a UEFI capsule that updates the firmware
                        * to this chid. sd-stub applies it unless the running system already reports this
                        * chid.
                        */

        /* next comes payload which is fwid and efi firmware binary blob */
        uint8_t payload[] _alignas_(uint64_t);
} EfiFwHeader;

assert_cc(offsetof(EfiFwHeader, chid) == 16);
assert_cc(offsetof(EfiFwHeader, payload) == 16 + sizeof(EFI_GUID));

EFI_STATUS efi_firmware_match_by_fwid(const void *blob, size_t blob_len, const char *fwid);

EFI_STATUS efi_firmware_get_capsule(
                const void *blob,
                size_t blob_len,
                const char **ret_fwid,
                const EFI_GUID **ret_chid,
                const void **ret_payload,
                size_t *ret_payload_len);

EFI_STATUS efi_firmware_apply_capsule(const void *payload, size_t payload_len);
