/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const VOID *linux_buffer, UINTN linux_length,
                const VOID *initrd_buffer, UINTN initrd_length);
