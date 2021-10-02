/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS linux_exec(
        EFI_HANDLE image,
        CHAR8* cmdline, UINTN cmdline_size,
        VOID* linux_buffer, UINTN linux_length,
        VOID* initrd_buffer, UINTN initrd_size);
