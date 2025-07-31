/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-firmware.h"
#include "efi-string.h"

static bool efifw_validate_header(
                const void *blob,
                size_t blob_len,
                const char **ret_fwid,
                const char **ret_payload) {

        if ((uintptr_t) blob % alignof(EfiFwHeader) != 0)
                return false;

        size_t base_sz = offsetof(EfiFwHeader, payload);

        /* at least the base size of the header must be in memory */
        if (blob_len < base_sz)
                return false;

        const EfiFwHeader *fw_header = ASSERT_PTR(blob);

        if (fw_header->magic != FWHEADERMAGIC)
                return false;

        uint32_t header_len  = fw_header->header_len;

        /* header_len must not be malformed */
        if (header_len < base_sz)
                return false;

        uint32_t fwid_len    = fw_header->fwid_len;
        uint32_t payload_len = fw_header->payload_len;
        size_t total_computed_size;

        /* check for unusually large values of payload_len, header_len or fwid_len */
        if (!ADD_SAFE(&total_computed_size, header_len, fwid_len) ||
            !ADD_SAFE(&total_computed_size, total_computed_size, payload_len))
                return false;

        /* see if entire size of the base header is present in memory */
        if (blob_len < total_computed_size)
                return false;

        const char *fwid    = (const char*) blob + header_len;
        const char *payload = fwid + fwid_len;

        /* check that fwid points to a NUL terminated string */
        if (memchr(fwid, 0, fwid_len) != fwid + fwid_len - 1)
                return false;

        if (ret_fwid)
                *ret_fwid = fwid;

        if (ret_payload)
                *ret_payload = payload;
        return true;
}

EFI_STATUS efi_firmware_match_by_fwid(
                const void *blob,
                size_t blob_len,
                const char *fwid) {

        assert(blob);
        assert(fwid);

        const char *blob_fwid;
        if (!efifw_validate_header(blob, blob_len, &blob_fwid, NULL))
                return EFI_INVALID_PARAMETER;

        return streq8(blob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
