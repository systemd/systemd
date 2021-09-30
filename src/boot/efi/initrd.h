/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS initrd_register(
                const VOID *initrd_address,
                UINTN initrd_length,
                EFI_HANDLE *ret_initrd_handle);

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle);
