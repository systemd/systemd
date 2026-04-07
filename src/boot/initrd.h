/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "iovec-util-fundamental.h"
#include "util.h"

EFI_STATUS initrd_register(
                const struct iovec *initrd,
                EFI_HANDLE *ret_initrd_handle);

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle);

static inline void cleanup_initrd(EFI_HANDLE *initrd_handle) {
        (void) initrd_unregister(*initrd_handle);
        *initrd_handle = NULL;
}

EFI_STATUS initrd_read_previous(struct iovec *ret_initrd);

EFI_STATUS combine_initrds(const struct iovec initrds[], size_t n_initrds, Pages *ret_initrd_pages, size_t *ret_initrd_size);
