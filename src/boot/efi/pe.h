/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "uki.h"

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address);

typedef struct {
        char name[9];
        size_t offset;
        size_t size;
} PeSectionDescriptor;

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections);

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections);

PeSectionDescriptor *pe_find_section(
                PeSectionDescriptor *sections,
                size_t n_sections,
                const char *section_name);

PeSectionDescriptor *pe_find_unified_section(
                PeSectionDescriptor *sections,
                size_t n_sections,
                UnifiedSection unified_section);