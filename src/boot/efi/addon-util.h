/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "proto/loaded-image.h"
#include "device-path-util.h"
#include "util.h"

#define SYSTEMD_ADDON_MEDIA_GUID \
        GUID_DEF(0x97ac68bf, 0xc741, 0x4bbb, 0xb7, 0xbf, 0x7f, 0x6c, 0xcc, 0x00, 0x8a, 0x7e)

static inline void unload_addons(EFI_HANDLE *addons) {
        // TODO: unload the installed protocol?
}

static inline bool is_addons_path(VENDOR_DEVICE_PATH *dp) {
        return (dp->Header.Type == MEDIA_DEVICE_PATH &&
                dp->Header.SubType == MEDIA_VENDOR_DP &&
                memcmp(&dp->Guid, MAKE_GUID_PTR(SYSTEMD_ADDON_MEDIA), sizeof(EFI_GUID)) == 0
               );
}

EFI_STATUS addons_install(EFI_LOADED_IMAGE_PROTOCOL *loaded_image, const char16_t **addons);
EFI_STATUS walk_addons_in_device_path(EFI_DEVICE_PATH *addons_dp, char16_t **files);
