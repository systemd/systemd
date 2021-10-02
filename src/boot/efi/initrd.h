/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define LINUX_INITRD_MEDIA_GUID                        \
     {0x5568e427, 0x68fc, 0x4f3d, {0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68} }

EFI_STATUS initrd_register(
        VOID* initrd_buffer,
        UINTN initrd_length
);

EFI_STATUS initrd_deregister(void);
