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
