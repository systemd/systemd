/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efi-string.h"
#include "proto/device-path.h"
#include "url-discovery.h"

char16_t *disk_get_url(EFI_HANDLE *handle) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        /* export the device path this image is started from */

        if (!handle)
                return NULL;

        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return NULL;

        for (; !device_path_is_end(dp); dp = device_path_next_node(dp)) {
                if (dp->Type != MESSAGING_DEVICE_PATH || dp->SubType != MSG_URI_DP)
                        continue;

                URI_DEVICE_PATH *udp = (URI_DEVICE_PATH*) dp;
                return xstrn8_to_16(udp->Uri, dp->Length);
        }

        return NULL;
}
