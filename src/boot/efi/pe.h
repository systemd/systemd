/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efidef.h>
#include <uchar.h>

EFI_STATUS pe_memory_locate_sections(
                const CHAR8 *base,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *sizes);

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                const CHAR8 **sections,
                UINTN *offsets,
                UINTN *sizes);

EFI_STATUS pe_alignment_info(
                const void *base,
                uint32_t *ret_entry_point_address,
                uint32_t *ret_size_of_image,
                uint32_t *ret_section_alignment);
