/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <stdbool.h>

EFI_STATUS linux_exec(
                EFI_HANDLE parent, bool is_signed,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length);
EFI_STATUS linux_exec_efi_handover(
                EFI_HANDLE parent,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length);
