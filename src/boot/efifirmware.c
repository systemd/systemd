/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efifirmware.h"
#include "util.h"
#include <endian.h>

static bool efifw_validate_header(
                const void *blob,
                size_t uki_efifw_len,
                void *ret_fwid_off,
                void *ret_payload_off) {

        if ((uintptr_t) blob % alignof(EfiFwHeader) != 0)
                return false;

        const EfiFwHeader *fw_header;

        /* at least the base size of the header must be in memory */
        if (uki_efifw_len < sizeof(fw_header->base))
                return false;

        fw_header = ASSERT_PTR(blob);

        if (fw_header->base.magic != FWHEADERMAGIC)
                return false;

        uint32_t payload_len = fw_header->base.payload_len;
        uint32_t header_len  = fw_header->base.header_len;
        uint32_t fwid_len    = fw_header->base.fwid_len;

        /* header_len must not be malformed */
        if (header_len < sizeof(fw_header->base))
                return false;

        size_t fw_base_size;

        /* check for unusually large values of payload_len, header_len or fwid_len */
        if (!ADD_SAFE(&fw_base_size, header_len, fwid_len) ||
            !ADD_SAFE(&fw_base_size, fw_base_size, payload_len) )
                return false;

        if (PTR_TO_SIZE(blob) > SIZE_MAX - fw_base_size)
                return false;

        size_t *fwid_off = NULL;
        size_t *payload_off = NULL;

        if (!ADD_SAFE(fwid_off, PTR_TO_SIZE(blob), header_len))
                return false;

        if (!ADD_SAFE(payload_off, PTR_TO_SIZE(fwid_off), fwid_len))
                return false;

        /* check that fwid_off points to a null terminated string of length < fwid_len */
        if (strlen((const char16_t *) fwid_off) >= fwid_len)
                return false;

        if (ret_fwid_off)
                ret_fwid_off = fwid_off;

        if (ret_payload_off)
                ret_payload_off = payload_off;
        return true;
}

static const char* efifw_get_fwid(
                const void *efifwblob,
                size_t uki_efifw_len) {

        const char* fwid;
        if (!efifw_validate_header(efifwblob, uki_efifw_len, &fwid, NULL))
                return NULL;

        return fwid;
}

EFI_STATUS efifirmware_match_by_fwid(
                const void *uki_efifw,
                size_t uki_efifw_length,
                const char *fwid) {

        assert(fwid);

        const char *fwblob_fwid = efifw_get_fwid(uki_efifw, uki_efifw_length);
        if (!fwblob_fwid)
                return EFI_INVALID_PARAMETER;

        return streq8(fwblob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
