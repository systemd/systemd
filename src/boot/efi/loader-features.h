/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
