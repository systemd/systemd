/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efi-efivars.h"
#include "export-vars.h"
#include "hii.h"
#include "measure.h"
#include "part-discovery.h"
#include "url-discovery.h"
#include "util.h"

void export_common_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        assert(loaded_image);

        /* Export the device path this image is started from, if it's not set yet */
        if (loaded_image->DeviceHandle) {
                if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                        _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
                        if (uuid)
                                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, /* flags= */ 0);
                }

                if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderDeviceURL", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                        _cleanup_free_ char16_t *url = disk_get_url(loaded_image->DeviceHandle);
                        if (url)
                                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderDeviceURL", url, /* flags= */ 0);
                }
        }

        /* If LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from the
         * UEFI firmware without any boot loader, and hence set the LoaderImageIdentifier ourselves. Note
         * that some boot chain loaders neither set LoaderImageIdentifier nor make FilePath available to us,
         * in which case there's simple nothing to set for us. (The UEFI spec doesn't really say who's wrong
         * here, i.e. whether FilePath may be NULL or not, hence handle this gracefully and check if FilePath
         * is non-NULL explicitly.) */
        if (loaded_image->FilePath &&
            efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                if (device_path_to_str(loaded_image->FilePath, &s) == EFI_SUCCESS)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", s, /* flags= */ 0);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("%ls %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", s, /* flags= */ 0);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", s, /* flags= */ 0);
        }

        /* ditto for LoaderTpm2ActivePcrBanks */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderTpm2ActivePcrBanks", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                uint32_t active_pcr_banks = tpm_get_active_pcr_banks();
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("0x%08x", active_pcr_banks);
                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderTpm2ActivePcrBanks", s, /* flags= */ 0);
        }

        /* Report the firmware's currently-active HII keyboard layout (as an RFC 4646 language tag, e.g.
         * "de-DE"), so the OS can pick a matching console keymap. Best-effort: many firmwares do not
         * implement the HII database protocol or expose no keyboard layout. */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderKeyboardLayout", /* ret_data= */ NULL, /* ret_size= */ NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *lang = hii_query_keyboard_layout_language();
                if (lang)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderKeyboardLayout", lang, /* flags= */ 0);
        }
}
