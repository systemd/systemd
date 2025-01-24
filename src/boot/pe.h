/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

/* This is the actual PE format of the section header */
typedef struct PeSectionHeader {
        uint8_t  Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
} _packed_ PeSectionHeader;

/* This is a subset of the full PE section header structure, with validated values, and without
 * the noise. */
typedef struct PeSectionVector {
        size_t memory_size;     /* Size of the section in memory (corresponds to VirtualSize field) */
        size_t memory_offset;   /* Offset in memory, relative to base address */
        uint64_t file_size;     /* Amount of bytes of the section read from disk (possibly aligned to FileAlignment in case VirtualSize > SizeOfRawData). */
        uint64_t file_offset;   /* Offset on disk, relative to beginning of file */
} PeSectionVector;

static inline bool PE_SECTION_VECTOR_IS_SET(const PeSectionVector *v) {
        return v && v->memory_size != 0;
}

EFI_STATUS pe_section_table_from_base(
                const void *base,
                const PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table);

EFI_STATUS pe_section_table_from_file(
                EFI_FILE *handle,
                PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table);

EFI_STATUS pe_locate_profile_sections(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char* const section_names[],
                unsigned profile,
                size_t validate_base,
                PeSectionVector sections[]);

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char *const section_names[],
                PeSectionVector sections[]);

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address, size_t *ret_size_in_memory);
