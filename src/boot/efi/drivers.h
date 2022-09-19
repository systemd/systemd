/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS reconnect_all_drivers(void);
EFI_STATUS load_drivers(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                EFI_FILE *root_dir);
