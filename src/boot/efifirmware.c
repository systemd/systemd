/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efifirmware.h"
#include "util.h"
#include <endian.h>

static bool efifw_validate_header(
                const void *blob,
                size_t blob_len,
                void *ret_fwid_off,
                void *ret_payload_off) {

        if ((uintptr_t) blob % alignof(EfiFwHeader) != 0)
                return false;

        /* at least the base size of the header must be in memory */
        if (blob_len < sizeof_field(EfiFwHeader, base))
                return false;

        const EfiFwHeader *fw_header = ASSERT_PTR(blob);

        if (fw_header->base.magic != FWHEADERMAGIC)
                return false;

        uint32_t header_len  = fw_header->base.header_len;

        /* header_len must not be malformed */
        if (header_len < sizeof_field(EfiFwHeader, base))
                return false;

        uint32_t fwid_len    = fw_header->base.fwid_len;
        uint32_t payload_len = fw_header->base.payload_len;
        size_t fw_base_size;

        /* check for unusually large values of payload_len, header_len or fwid_len */
        if (!ADD_SAFE(&fw_base_size, header_len, fwid_len) ||
            !ADD_SAFE(&fw_base_size, fw_base_size, payload_len) )
                return false;

        /* see if entire size of the base header is present in memory */
        if (blob_len < fw_base_size)
                return false;

        unsigned char *fwid_off    = (unsigned char*)blob + header_len;
        unsigned char *payload_off = fwid_off + fwid_len;

        /* check that fwid_off contains NULL character within fwid_len */
        if (!memchr(fwid_off, 0, fwid_len))
                return false;

        if (ret_fwid_off)
                ret_fwid_off = fwid_off;

        if (ret_payload_off)
                ret_payload_off = payload_off;
        return true;
}

static const char* efifw_get_fwid(
                const void *efifwblob,
                size_t efifwblob_len) {

        const char* fwid;
        if (!efifw_validate_header(efifwblob, efifwblob_len, &fwid, NULL))
                return NULL;

        return fwid;
}

EFI_STATUS efifirmware_match_by_fwid(
                const void *uki_efifw,
                size_t uki_efifw_len,
                const char *fwid) {

        assert(fwid);

        const char *fwblob_fwid = efifw_get_fwid(uki_efifw, uki_efifw_len);
        if (!fwblob_fwid)
                return EFI_INVALID_PARAMETER;

        return streq8(fwblob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
