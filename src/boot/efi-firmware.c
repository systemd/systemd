/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-firmware.h"
#include "efi-log.h"
#include "efi-string.h"
#include "util.h"

static bool efifw_validate_header(
                const void *blob,
                size_t blob_len,
                const char **ret_fwid,
                const EFI_GUID **ret_chid,
                const void **ret_payload,
                size_t *ret_payload_len) {

        if ((uintptr_t) blob % alignof(EfiFwHeader) != 0)
                return false;

        /* chid is optional, so the minimum header is everything up to it. */
        size_t base_sz = offsetof(EfiFwHeader, chid);

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

        const EFI_GUID *chid = NULL;
        if (header_len >= offsetof(EfiFwHeader, chid) + sizeof(EFI_GUID) &&
            !efi_guid_is_zero(&fw_header->chid))
                chid = &fw_header->chid;

        if (ret_fwid)
                *ret_fwid = fwid;

        if (ret_chid)
                *ret_chid = chid;

        if (ret_payload)
                *ret_payload = payload;

        if (ret_payload_len)
                *ret_payload_len = payload_len;

        return true;
}

EFI_STATUS efi_firmware_match_by_fwid(
                const void *blob,
                size_t blob_len,
                const char *fwid) {

        assert(blob);
        assert(fwid);

        const char *blob_fwid;
        if (!efifw_validate_header(blob, blob_len, &blob_fwid, NULL, NULL, NULL))
                return EFI_INVALID_PARAMETER;

        return streq8(blob_fwid, fwid) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

EFI_STATUS efi_firmware_get_capsule(
                const void *blob,
                size_t blob_len,
                const char **ret_fwid,
                const EFI_GUID **ret_chid,
                const void **ret_payload,
                size_t *ret_payload_len) {

        assert(blob);
        assert(ret_chid);
        assert(ret_fwid);
        assert(ret_payload);
        assert(ret_payload_len);

        if (!efifw_validate_header(blob, blob_len, ret_fwid, ret_chid, ret_payload, ret_payload_len))
                return EFI_INVALID_PARAMETER;

        return EFI_SUCCESS;
}

EFI_STATUS efi_firmware_apply_capsule(const void *payload, size_t payload_len) {
        EFI_STATUS err;

        assert(payload);

        if (payload_len < sizeof(EFI_CAPSULE_HEADER))
                return log_error_status(EFI_INVALID_PARAMETER, "Capsule payload smaller than its header.");

        EFI_CAPSULE_HEADER header;
        memcpy(&header, payload, sizeof(header));

        if (header.CapsuleImageSize != payload_len)
                return log_error_status(EFI_INVALID_PARAMETER,
                                        "Capsule image size (%u) does not match payload length (%zu).",
                                        header.CapsuleImageSize, payload_len);

        if (header.HeaderSize < sizeof(EFI_CAPSULE_HEADER) || header.HeaderSize > header.CapsuleImageSize)
                return log_error_status(EFI_INVALID_PARAMETER,
                                        "Capsule header size (%u) out of range.", header.HeaderSize);

        bool persist = FLAGS_SET(header.Flags, CAPSULE_FLAGS_PERSIST_ACROSS_RESET);

        /* The staged capsule and its scatter-gather list must survive UpdateCapsule()/ResetSystem(), so they
         * are RuntimeServicesData. On the success path ResetSystem() never returns, so these cleanup
         * destructors only ever run on the error paths below. */
        _cleanup_pages_ Pages capsule_pages = xmalloc_pages(
                        AllocateAnyPages,
                        EfiRuntimeServicesData,
                        EFI_SIZE_TO_PAGES(payload_len),
                        0);
        void *staged = PHYSICAL_ADDRESS_TO_POINTER(capsule_pages.addr);
        memcpy(staged, payload, payload_len);

        EFI_CAPSULE_HEADER *array[1] = { staged };

        uint64_t max_size = 0;
        EFI_RESET_TYPE reset_type = EfiResetCold;
        err = RT->QueryCapsuleCapabilities(array, 1, &max_size, &reset_type);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "QueryCapsuleCapabilities failed: %m");

        if (header.CapsuleImageSize > max_size)
                return log_error_status(EFI_UNSUPPORTED,
                                        "Capsule (%u bytes) exceeds firmware maximum (%" PRIu64 " bytes).",
                                        header.CapsuleImageSize, max_size);

        _cleanup_pages_ Pages descriptor_pages = {};
        EFI_PHYSICAL_ADDRESS sgl = 0;
        if (persist) {
                descriptor_pages = xmalloc_pages(
                                AllocateAnyPages,
                                EfiRuntimeServicesData,
                                EFI_SIZE_TO_PAGES(2 * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR)),
                                0);
                EFI_CAPSULE_BLOCK_DESCRIPTOR *desc = PHYSICAL_ADDRESS_TO_POINTER(descriptor_pages.addr);
                desc[0] = (EFI_CAPSULE_BLOCK_DESCRIPTOR) {
                        .Length = header.CapsuleImageSize,
                        .Union.DataBlock = capsule_pages.addr,
                };
                desc[1] = (EFI_CAPSULE_BLOCK_DESCRIPTOR) {};
                sgl = descriptor_pages.addr;
        }

        err = RT->UpdateCapsule(array, 1, sgl);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "UpdateCapsule failed: %m");

        /* If the capsule set INITIATE_RESET the firmware already reset inside UpdateCapsule and we never got
         * here. Otherwise we must reset ourselves to drive the chid recheck on the next boot. */
        RT->ResetSystem(reset_type, EFI_SUCCESS, 0, NULL);
        return log_error_status(EFI_LOAD_ERROR, "ResetSystem returned after applying firmware capsule.");
}
