/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "disk.h"
#include "util.h"

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, CHAR16 uuid[static 37]) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        /* export the device path this image is started from */

        if (!handle)
                return EFI_NOT_FOUND;

        err = BS->HandleProtocol(handle, &DevicePathProtocol, (void **) &dp);
        if (err != EFI_SUCCESS)
                return err;

        for (; !IsDevicePathEnd(dp); dp = NextDevicePathNode(dp)) {
                if (DevicePathType(dp) != MEDIA_DEVICE_PATH)
                        continue;
                if (DevicePathSubType(dp) != MEDIA_HARDDRIVE_DP)
                        continue;

                HARDDRIVE_DEVICE_PATH *hd = (HARDDRIVE_DEVICE_PATH *) dp;
                if (hd->SignatureType != SIGNATURE_TYPE_GUID)
                        continue;

                snprintf(uuid, 37,
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         hd->Signature[3], hd->Signature[2],
                         hd->Signature[1], hd->Signature[0],

                         hd->Signature[5], hd->Signature[4],
                         hd->Signature[7], hd->Signature[6],

                         hd->Signature[8], hd->Signature[9],
                         hd->Signature[10], hd->Signature[11],
                         hd->Signature[12], hd->Signature[13],
                         hd->Signature[14], hd->Signature[15]);
                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}
