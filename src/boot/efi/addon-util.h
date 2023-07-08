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

EFI_STATUS addons_install(EFI_LOADED_IMAGE_PROTOCOL *loaded_image, const char16_t **addons);
