/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efifirmware.h"
#include "util.h"

static const char* efifw_get_fwid(const void *efifwblob) {
        if ((uintptr_t) efifwblob % alignof(EfiFwHeader) != 0)
                return NULL;

        const EfiFwHeader *fw_header = ASSERT_PTR(efifwblob);

        if (be32toh(fw_header->magic) != UINT32_C(FWHEADERMAGIC))
                return NULL;

        uint32_t fw_size = be32toh(fw_header->total_size);
        uint32_t fw_metadata_off = be32toh(fw_header->fw_metadata_offset);
        uint32_t fw_metadata_len = be32toh(fw_header->fw_metadata_len);
        uint32_t fwid_off = be32toh(fw_header->fwid_offset);
        uint32_t fwid_len = be32toh(fw_header->fwid_len);
        uint32_t payload_off = be32toh(fw_header->payload_offset);
        uint32_t payload_len = be32toh(fw_header->payload_len);
        uint32_t end;

        if (PTR_TO_SIZE(efifwblob) > SIZE_MAX - fw_size)
                return NULL;

        if (!ADD_SAFE(&end, fw_metadata_off, fw_metadata_len) || end > fw_size)
                return NULL;

        if (!ADD_SAFE(&end, fwid_off, fwid_len) || end > fw_size)
                return NULL;

        if (!ADD_SAFE(&end, payload_off, payload_len) || end > fw_size)
                return NULL;

        const char *fwid = (const char *) ((const uint8_t *) fw_header + fwid_off);

        return fwid;
}

EFI_STATUS efifirmware_match_by_fwid(const void *uki_efifw, size_t uki_efifw_length, const char *fwid)
{
        if ((uintptr_t) uki_efifw % alignof(EfiFwHeader) != 0)
                return EFI_INVALID_PARAMETER;

        const EfiFwHeader *fw_header = ASSERT_PTR(uki_efifw);

        if (uki_efifw_length < sizeof(EfiFwHeader) ||
            uki_efifw_length < be32toh(fw_header->total_size))
                return EFI_INVALID_PARAMETER;

        if (!fwid)
                return EFI_INVALID_PARAMETER;

        const char *fwblob_fwid = efifw_get_fwid(uki_efifw);
        if (!fwblob_fwid)
                return EFI_INVALID_PARAMETER;

        return streq8(fwblob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
