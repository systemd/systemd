/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_EDID_DISCOVERED_PROTOCOL_GUID \
        GUID_DEF(0x1c0c34f6, 0xd380, 0x41fa, 0xa0, 0x49, 0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa)

typedef struct {
        uint32_t SizeOfEdid;
        uint8_t *Edid;
} EFI_EDID_DISCOVERED_PROTOCOL;
