/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <efi.h>

typedef enum RandomSeedMode {
        RANDOM_SEED_OFF,
        RANDOM_SEED_WITH_SYSTEM_TOKEN,
        RANDOM_SEED_ALWAYS,
        _RANDOM_SEED_MODE_MAX,
        _RANDOM_SEED_MODE_INVALID = -1,
} RandomSeedMode;

EFI_STATUS process_random_seed(EFI_FILE *root_dir, RandomSeedMode mode);
