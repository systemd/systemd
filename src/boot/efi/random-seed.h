/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <errno.h>
#include <uchar.h>

typedef enum RandomSeedMode {
        RANDOM_SEED_OFF,
        RANDOM_SEED_WITH_SYSTEM_TOKEN,
        RANDOM_SEED_ALWAYS,
        _RANDOM_SEED_MODE_MAX,
        _RANDOM_SEED_MODE_INVALID = -EINVAL,
} RandomSeedMode;

static const char16_t * const random_seed_modes_table[_RANDOM_SEED_MODE_MAX] = {
        [RANDOM_SEED_OFF]               = L"off",
        [RANDOM_SEED_WITH_SYSTEM_TOKEN] = L"with-system-token",
        [RANDOM_SEED_ALWAYS]            = L"always",
};

EFI_STATUS process_random_seed(EFI_FILE *root_dir, RandomSeedMode mode);
