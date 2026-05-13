/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

struct linux_efi_random_seed {
        uint32_t size;
        uint8_t seed[];
};

#define LINUX_EFI_RANDOM_SEED_TABLE_GUID \
        { 0x1ce1e5bc, 0x7ceb, 0x42f2, { 0x81, 0xe5, 0x8a, 0xad, 0xf1, 0x80, 0xf5, 0x7b } }

EFI_STATUS process_random_seed(EFI_FILE *root_dir);
