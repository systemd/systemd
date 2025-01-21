/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efifirmware.h"
#include "util.h"
#include <endian.h>

static bool efifw_validate_header(const void *blob, size_t uki_efifw_len,
                                  uint32_t *fwid_off, uint32_t *payload_off) {
        if ((uintptr_t) blob % alignof(EfiFwHeader) != 0)
                return false;
        const EfiFwHeader *fw_header = ASSERT_PTR(blob);

        if (le32toh(fw_header->base.magic) != FWHEADERMAGIC)
                return false;

        size_t payload_len = le32toh(fw_header->base.payload_len);
        size_t header_len = le32toh(fw_header->base.header_len);
        size_t fwid_len = le32toh(fw_header->base.fwid_len);

         /* at least entire base header must be present */
        if (header_len < sizeof (fw_header->base))
                return false;

        size_t fw_base_size = header_len + fwid_len + payload_len;

        if (uki_efifw_len < sizeof(EfiFwHeader) ||
            uki_efifw_len < fw_base_size)
                return false;

        if (PTR_TO_SIZE(blob) > SIZE_MAX - fw_base_size)
                return false;

        if (!ADD_SAFE(fwid_off, PTR_TO_SIZE(blob), header_len))
                return false;

        if (!ADD_SAFE(payload_off, *fwid_off, fwid_len))
                return false;

        return true;
}

static const char* efifw_get_fwid(const void *efifwblob, size_t uki_efifw_len) {

        uint32_t fwid, payload;
        if (!efifw_validate_header(efifwblob, uki_efifw_len, &fwid, &payload))
                return NULL;

        return (const char *) ((const uintptr_t) fwid);
}

EFI_STATUS efifirmware_match_by_fwid(const void *uki_efifw, size_t uki_efifw_length,
                                     const char *fwid) {
        assert(fwid);

        const char *fwblob_fwid = efifw_get_fwid(uki_efifw, uki_efifw_length);
        if (!fwblob_fwid)
                return EFI_INVALID_PARAMETER;

        return streq8(fwblob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
