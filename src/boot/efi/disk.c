/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 */

#include <efi.h>
#include <efilib.h>

#include "util.h"

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, CHAR16 uuid[37]) {
        EFI_DEVICE_PATH *device_path;
        EFI_STATUS r = EFI_NOT_FOUND;

        /* export the device path this image is started from */
        device_path = DevicePathFromHandle(handle);
        if (device_path) {
                EFI_DEVICE_PATH *path, *paths;

                paths = UnpackDevicePath(device_path);
                for (path = paths; !IsDevicePathEnd(path); path = NextDevicePathNode(path)) {
                        HARDDRIVE_DEVICE_PATH *drive;

                        if (DevicePathType(path) != MEDIA_DEVICE_PATH)
                                continue;
                        if (DevicePathSubType(path) != MEDIA_HARDDRIVE_DP)
                                continue;
                        drive = (HARDDRIVE_DEVICE_PATH *)path;
                        if (drive->SignatureType != SIGNATURE_TYPE_GUID)
                                continue;

                        GuidToString(uuid, (EFI_GUID *)&drive->Signature);
                        r = EFI_SUCCESS;
                        break;
                }
                FreePool(paths);
        }

        return r;
}
