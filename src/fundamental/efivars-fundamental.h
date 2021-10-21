/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include "string-util-fundamental.h"

#ifndef UINT64_C
#  define UINT64_C(c) (c ## ULL)
#endif

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
        SECURE_BOOT_UNKNOWN,
        SECURE_BOOT_AUDIT,
        SECURE_BOOT_DEPLOYED,
        SECURE_BOOT_SETUP,
        SECURE_BOOT_USER,
        _SECURE_BOOT_MAX,
        _SECURE_BOOT_INVALID = -EINVAL,
} SecureBootMode;

static inline const sd_char *secure_boot_mode_to_string(SecureBootMode m) {
        static const sd_char * const table[_SECURE_BOOT_MAX] = {
                [SECURE_BOOT_UNSUPPORTED] = STR_C("unsupported"),
                [SECURE_BOOT_UNKNOWN]     = STR_C("unknown"),
                [SECURE_BOOT_AUDIT]       = STR_C("audit"),
                [SECURE_BOOT_DEPLOYED]    = STR_C("deployed"),
                [SECURE_BOOT_SETUP]       = STR_C("setup"),
                [SECURE_BOOT_USER]        = STR_C("user"),
        };
        return (m >= 0 && m < _SECURE_BOOT_MAX) ? table[m] : NULL;
}

static inline SecureBootMode decode_secure_boot_mode(
                sd_bool secure,
                sd_bool audit,
                sd_bool deployed,
                sd_bool setup) {

        /* See figure 32-4 Secure Boot Modes from UEFI Specification 2.9 */
        if (secure && deployed && !audit && !setup)
                return SECURE_BOOT_DEPLOYED;
        if (secure && !deployed && !audit && !setup)
                return SECURE_BOOT_USER;
        if (!secure && !deployed && audit && setup)
                return SECURE_BOOT_AUDIT;
        if (!secure && !deployed && !audit && setup)
                return SECURE_BOOT_SETUP;

        /* Well, this should not happen. */
        return SECURE_BOOT_UNKNOWN;
}
