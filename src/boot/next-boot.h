/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS next_boot_image(
                EFI_HANDLE device,
                const char16_t *path,
                const char16_t *options,
                const char16_t *title);
