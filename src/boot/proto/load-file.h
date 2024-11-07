/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_LOAD_FILE_PROTOCOL_GUID \
        GUID_DEF(0x56EC3091, 0x954C, 0x11d2, 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
#define EFI_LOAD_FILE2_PROTOCOL_GUID \
        GUID_DEF(0x4006c0c1, 0xfcb3, 0x403e, 0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d)

typedef struct EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE_PROTOCOL;
typedef EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE2_PROTOCOL;

struct EFI_LOAD_FILE_PROTOCOL {
        EFI_STATUS (EFIAPI *LoadFile)(
                        EFI_LOAD_FILE_PROTOCOL *This,
                        EFI_DEVICE_PATH *FilePath,
                        bool BootPolicy,
                        size_t *BufferSize,
                        void *Buffer);
};
