/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_SECURITY_ARCH_PROTOCOL_GUID \
        GUID_DEF(0xA46423E3, 0x4617, 0x49f1, 0xB9, 0xFF, 0xD1, 0xBF, 0xA9, 0x11, 0x58, 0x39)
#define EFI_SECURITY2_ARCH_PROTOCOL_GUID \
        GUID_DEF(0x94ab2f58, 0x1438, 0x4ef1, 0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68)

typedef struct EFI_SECURITY_ARCH_PROTOCOL EFI_SECURITY_ARCH_PROTOCOL;
typedef struct EFI_SECURITY2_ARCH_PROTOCOL EFI_SECURITY2_ARCH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE)(
                const EFI_SECURITY_ARCH_PROTOCOL *This,
                uint32_t AuthenticationStatus,
                const EFI_DEVICE_PATH *File);

typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION)(
                const EFI_SECURITY2_ARCH_PROTOCOL *This,
                const EFI_DEVICE_PATH *DevicePath,
                void *FileBuffer,
                size_t FileSize,
                bool BootPolicy);

struct EFI_SECURITY_ARCH_PROTOCOL {
        EFI_SECURITY_FILE_AUTHENTICATION_STATE FileAuthenticationState;
};

struct EFI_SECURITY2_ARCH_PROTOCOL {
        EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};
