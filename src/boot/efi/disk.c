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

        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
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

                _cleanup_free_ char16_t *tmp = xasprintf(
                                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                hd.Signature[3],
                                hd.Signature[2],
                                hd.Signature[1],
                                hd.Signature[0],

                                hd.Signature[5],
                                hd.Signature[4],
                                hd.Signature[7],
                                hd.Signature[6],

                                hd.Signature[8],
                                hd.Signature[9],
                                hd.Signature[10],
                                hd.Signature[11],
                                hd.Signature[12],
                                hd.Signature[13],
                                hd.Signature[14],
                                hd.Signature[15]);
                strcpy16(uuid, tmp);
                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}
