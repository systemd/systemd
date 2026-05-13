/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID \
        GUID_DEF(0xf4560cf6, 0x40ec, 0x4b4a, 0xa1, 0x92, 0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89)

#define EFI_MEMORY_RP 0x0000000000002000
#define EFI_MEMORY_XP 0x0000000000004000
#define EFI_MEMORY_RO 0x0000000000020000

struct _EFI_MEMORY_ATTRIBUTE_PROTOCOL;

typedef struct _EFI_MEMORY_ATTRIBUTE_PROTOCOL {
        EFI_STATUS (EFIAPI *GetMemoryAttributes)(
                        struct _EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                        EFI_PHYSICAL_ADDRESS BaseAddress,
                        uint64_t Length,
                        uint64_t *Attributes);
        EFI_STATUS (EFIAPI *SetMemoryAttributes)(
                        struct _EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                        EFI_PHYSICAL_ADDRESS BaseAddress,
                        uint64_t Length,
                        uint64_t Attributes);
        EFI_STATUS (EFIAPI *ClearMemoryAttributes)(
                        struct _EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                        EFI_PHYSICAL_ADDRESS BaseAddress,
                        uint64_t Length,
                        uint64_t Attributes);
} EFI_MEMORY_ATTRIBUTE_PROTOCOL;
