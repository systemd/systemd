/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efivars.h"
#include "export-vars.h"
#include "part-discovery.h"
#include "util.h"

void export_common_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        assert(loaded_image);

        /* Export the device path this image is started from, if it's not set yet */
        if (loaded_image->DeviceHandle &&
            efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
                if (uuid)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, 0);
        }

        /* If LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from the
         * UEFI firmware without any boot loader, and hence set the LoaderImageIdentifier ourselves. Note
         * that some boot chain loaders neither set LoaderImageIdentifier nor make FilePath available to us,
         * in which case there's simple nothing to set for us. (The UEFI spec doesn't really say who's wrong
         * here, i.e. whether FilePath may be NULL or not, hence handle this gracefully and check if FilePath
         * is non-NULL explicitly.) */
        if (loaded_image->FilePath &&
            efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                if (device_path_to_str(loaded_image->FilePath, &s) == EFI_SUCCESS)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", s, 0);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("%ls %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", s, 0);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_free_ char16_t *s = NULL;
                s = xasprintf("UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set_str16(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", s, 0);
        }
}
