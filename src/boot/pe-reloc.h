/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

/* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_DIR64    10

EFI_STATUS pe_apply_base_relocations(
                uint8_t *loaded_base,
                size_t loaded_size,
                uint32_t reloc_rva,
                uint32_t reloc_size,
                uint64_t delta);
