/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

EFI_STATUS pe_memory_locate_sections(CHAR8 *base, CHAR8 **sections, UINTN *addrs, UINTN *offsets, UINTN *sizes);
EFI_STATUS pe_file_locate_sections(EFI_FILE *dir, CHAR16 *path, CHAR8 **sections, UINTN *addrs, UINTN *offsets, UINTN *sizes);
