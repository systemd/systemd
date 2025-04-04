/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_PXE_BASE_CODE_PROTOCOL_GUID \
        GUID_DEF(0x03c4e603, 0xac28, 0x11d3, 0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)

typedef struct {
        void *noop;
} EFI_PXE_BASE_CODE_PROTOCOL;
