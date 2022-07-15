/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include "string-util-fundamental.h"

#define EFI_LOADER_FEATURE_CONFIG_TIMEOUT          (UINT64_C(1) << 0)
#define EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT (UINT64_C(1) << 1)
#define EFI_LOADER_FEATURE_ENTRY_DEFAULT           (UINT64_C(1) << 2)
#define EFI_LOADER_FEATURE_ENTRY_ONESHOT           (UINT64_C(1) << 3)
#define EFI_LOADER_FEATURE_BOOT_COUNTING           (UINT64_C(1) << 4)
#define EFI_LOADER_FEATURE_XBOOTLDR                (UINT64_C(1) << 5)
#define EFI_LOADER_FEATURE_RANDOM_SEED             (UINT64_C(1) << 6)
#define EFI_LOADER_FEATURE_LOAD_DRIVER             (UINT64_C(1) << 7)

typedef enum SecureBootMode {
        SECURE_BOOT_UNSUPPORTED,
        SECURE_BOOT_DISABLED,
        SECURE_BOOT_UNKNOWN,
        SECURE_BOOT_AUDIT,
        SECURE_BOOT_DEPLOYED,
        SECURE_BOOT_SETUP,
        SECURE_BOOT_USER,
        _SECURE_BOOT_MAX,
        _SECURE_BOOT_INVALID = -EINVAL,
} SecureBootMode;

const sd_char *secure_boot_mode_to_string(SecureBootMode m);
SecureBootMode decode_secure_boot_mode(bool secure, bool audit, bool deployed, bool setup);
