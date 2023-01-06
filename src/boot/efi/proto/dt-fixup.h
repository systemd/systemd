/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_DTB_TABLE_GUID \
        GUID_DEF(0xb1b621d5, 0xf19c, 0x41a5, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0)
#define EFI_DT_FIXUP_PROTOCOL_GUID \
        GUID_DEF(0xe617d64c, 0xfe08, 0x46da, 0xf4, 0xdc, 0xbb, 0xd5, 0x87, 0x0c, 0x73, 0x00)

#define EFI_DT_FIXUP_PROTOCOL_REVISION 0x00010000

/* Add nodes and update properties */
#define EFI_DT_APPLY_FIXUPS 0x00000001

/*
 * Reserve memory according to the /reserved-memory node
 * and the memory reservation block
 */
#define EFI_DT_RESERVE_MEMORY 0x00000002

typedef struct EFI_DT_FIXUP_PROTOCOL EFI_DT_FIXUP_PROTOCOL;
struct EFI_DT_FIXUP_PROTOCOL {
        uint64_t Revision;
        EFI_STATUS (EFIAPI *Fixup)(
                EFI_DT_FIXUP_PROTOCOL *This,
                void *Fdt,
                size_t *BufferSize,
                uint32_t Flags);
};
