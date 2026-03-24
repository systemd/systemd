/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "pe.h"
#include "proto/loaded-image.h"

#define BOOT_SECRET_SIZE 32U

EFI_STATUS prepare_boot_secret(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *osrel_section,
                uint8_t ret[static BOOT_SECRET_SIZE]);
