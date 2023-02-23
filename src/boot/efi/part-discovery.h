/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define XBOOTLDR_GUID \
        { 0xbc13c2ff, 0x59e6, 0x4262, { 0xa3, 0x52, 0xb2, 0x75, 0xfd, 0x6f, 0x71, 0x72 } }
#define ESP_GUID \
        { 0xc12a7328, 0xf81f, 0x11d2, { 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b } }

EFI_STATUS partition_open(const EFI_GUID *type, EFI_HANDLE *device, EFI_HANDLE *ret_device, EFI_FILE **ret_root_dir);
char16_t *disk_get_part_uuid(EFI_HANDLE *handle);
