/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
  &(EFI_GUID)  { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }}

BOOLEAN secure_boot_enabled(void);
BOOLEAN setup_mode_enabled(void);
