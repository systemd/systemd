/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address);

struct PeSectionDescriptor {
        char name[9];
        size_t offset;
        size_t size;
};

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                struct PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections);

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                struct PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections);

struct PeSectionDescriptor *pe_bsearch_section(
                const struct PeSectionDescriptor *sections,
                size_t n_sections,
                const char *section_name);
