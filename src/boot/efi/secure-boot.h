/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include "efivars-fundamental.h"

#define EFI_IMAGE_SECURITY_DATABASE_VARIABLE \
        { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }}

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
        &(const EFI_GUID) EFI_IMAGE_SECURITY_DATABASE_VARIABLE

BOOLEAN secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);
