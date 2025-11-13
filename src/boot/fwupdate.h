/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define FWUPDATE_GUID { 0x0abba7dc, 0xe516, 0x4167, { 0xbb, 0xf5, 0x4d, 0x9d, 0x1c, 0x73, 0x94, 0x16 } }

EFI_STATUS fwupdate_get_boot_disk_path(EFI_HANDLE boot_device, EFI_DEVICE_PATH **ret_disk_path);
void fwupdate_install(const EFI_DEVICE_PATH *boot_disk_path);
