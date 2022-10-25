/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <stddef.h>

typedef struct Initrd Initrd;

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                Initrd **ret);

EFI_STATUS initrd_unregister(Initrd *initrd);

static inline void cleanup_initrd(Initrd **initrd) {
        (void) initrd_unregister(*initrd);
}
