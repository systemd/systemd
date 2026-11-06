/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "iovec-util.h"

#define ADDON_MEDIA_GUID \
        GUID_DEF(0x703430c9, 0x7b7f, 0x4ada, 0xb6, 0x47, 0x6c, 0x0e, 0xeb, 0x8b, 0xa4, 0x8f)

EFI_STATUS addon_media_register(const char16_t *filename, struct iovec *data, EFI_HANDLE *ret_handle);
EFI_STATUS addon_media_unregister(EFI_HANDLE handle);

static inline void cleanup_addon_media(EFI_HANDLE *handle) {
        (void) addon_media_unregister(*handle);
        *handle = NULL;
}

const char16_t* addon_media_filename(const EFI_DEVICE_PATH *dp);
EFI_STATUS addon_media_find(EFI_DEVICE_PATH ***ret_paths, size_t *ret_n_paths);
