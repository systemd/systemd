/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp);
EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret);
bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start);
EFI_DEVICE_PATH *device_path_replace_node(
                const EFI_DEVICE_PATH *path, const EFI_DEVICE_PATH *node, const EFI_DEVICE_PATH *new_node);
