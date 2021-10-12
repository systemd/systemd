/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efidef.h>

EFI_STATUS pe_memory_locate_sections(
                const CHAR8 *base,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *sizes);

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const CHAR16 *path,
                const CHAR8 **sections,
                UINTN *offsets,
                UINTN *sizes);

EFI_STATUS pe_alignment_info(
                const VOID *base,
                UINTN *ret_size_of_image,
                UINTN *ret_section_alignment);

EFI_IMAGE_ENTRY_POINT pe_entry_point(const VOID *base);
