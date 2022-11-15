/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efidef.h>
#include <uchar.h>

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char * const sections[],
                UINTN *addrs,
                UINTN *sizes);

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                const char * const sections[],
                UINTN *offsets,
                UINTN *sizes);

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address);
