/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
        GUID_DEF(0x5B1B31A1, 0x9562, 0x11d2, 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B)
#define EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID \
        GUID_DEF(0xbc62157e, 0x3e33, 0x4fec, 0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf)

typedef EFI_STATUS (EFIAPI *EFI_IMAGE_ENTRY_POINT)(
        EFI_HANDLE ImageHandle,
        EFI_SYSTEM_TABLE *SystemTable);

typedef struct {
        uint32_t Revision;
        EFI_HANDLE ParentHandle;
        EFI_SYSTEM_TABLE *SystemTable;
        EFI_HANDLE DeviceHandle;
        EFI_DEVICE_PATH *FilePath;
        void *Reserved;
        uint32_t LoadOptionsSize;
        void *LoadOptions;
        void *ImageBase;
        uint64_t ImageSize;
        EFI_MEMORY_TYPE ImageCodeType;
        EFI_MEMORY_TYPE ImageDataType;
        EFI_STATUS (EFIAPI *Unload)(EFI_HANDLE ImageHandle);
} EFI_LOADED_IMAGE_PROTOCOL;
