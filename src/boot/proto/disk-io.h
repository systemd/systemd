/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_DISK_IO_PROTOCOL_GUID \
        GUID_DEF(0xCE345171, 0xBA0B, 0x11d2, 0x8e, 0x4F, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

typedef struct EFI_DISK_IO_PROTOCOL EFI_DISK_IO_PROTOCOL;
struct EFI_DISK_IO_PROTOCOL {
        uint64_t Revision;
        EFI_STATUS (EFIAPI *ReadDisk)(
                        EFI_DISK_IO_PROTOCOL *This,
                        uint32_t MediaId,
                        uint64_t Offset,
                        size_t BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *WriteDisk)(
                        EFI_DISK_IO_PROTOCOL *This,
                        uint32_t MediaId,
                        uint64_t Offset,
                        size_t BufferSize,
                        const void *Buffer);
};
