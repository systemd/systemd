/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "util.h"

EFI_STATUS initrd_register(
                const void *initrd_address,
                size_t initrd_length,
                EFI_HANDLE *ret_initrd_handle);

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle);

static inline void cleanup_initrd(EFI_HANDLE *initrd_handle) {
        (void) initrd_unregister(*initrd_handle);
        *initrd_handle = NULL;
}

static inline Pages initrd_alloc_pages(size_t n_pages) {
#if defined(__i386__) || defined(__x86_64__)
        return xmalloc_pages(
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n_pages),
                        UINT32_MAX /* Below 4G boundary. */);
#else
        return xmalloc_pages(
                        AllocateAnyPages,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n_pages),
                        0 /* Ignored. */);
#endif
}
