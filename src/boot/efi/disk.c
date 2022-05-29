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

                /* Use memcpy in case the device path node is misaligned. */
                EFI_GUID sig;
                memcpy(&sig, hd->Signature, sizeof(hd->Signature));

                GuidToString(uuid, &sig);
                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}
