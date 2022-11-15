/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "disk.h"
#include "util.h"

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, char16_t uuid[static 37]) {
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

                /* The HD device path may be misaligned. */
                HARDDRIVE_DEVICE_PATH hd;
                memcpy(&hd, dp, MIN(sizeof(hd), (size_t) DevicePathNodeLength(dp)));

                if (hd.SignatureType != SIGNATURE_TYPE_GUID)
                        continue;

                GuidToString(uuid, (EFI_GUID *) &hd.Signature);
                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}
