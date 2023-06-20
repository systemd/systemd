/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS linux_exec(
                const char16_t *cmdline,
                const void *linux_buffer,
                size_t linux_length,
                const void *initrd_buffer,
                size_t initrd_length);
EFI_STATUS linux_exec_efi_handover(
                const char16_t *cmdline,
                const void *linux_buffer,
                size_t linux_length,
                const void *initrd_buffer,
                size_t initrd_length);
