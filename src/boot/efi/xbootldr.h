/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define XBOOTLDR_GUID \
        &(const EFI_GUID) { 0xbc13c2ff, 0x59e6, 0x4262, { 0xa3, 0x52, 0xb2, 0x75, 0xfd, 0x6f, 0x71, 0x72 } }

EFI_STATUS xbootldr_open(EFI_HANDLE *device, EFI_HANDLE *ret_device, EFI_FILE **ret_root_dir);
