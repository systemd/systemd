/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS graphics_splash(const uint8_t *content, UINTN len, const EFI_GRAPHICS_OUTPUT_BLT_PIXEL *background);
