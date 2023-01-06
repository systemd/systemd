/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                EFI_HANDLE *ret_initrd_handle);

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle);

static inline void cleanup_initrd(EFI_HANDLE *initrd_handle) {
        (void) initrd_unregister(*initrd_handle);
        *initrd_handle = NULL;
}
