/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

typedef struct InitrdLoader InitrdLoader;

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                EFI_HANDLE image,
                InitrdLoader **ret_loader);
EFI_STATUS initrd_unregister(InitrdLoader *loader);

static inline void cleanup_initrd(InitrdLoader **loader) {
        (void) initrd_unregister(*loader);
        *loader = NULL;
}
