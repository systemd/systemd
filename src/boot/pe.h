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

typedef enum PeLocateByOffset {
        PE_LOCATE_BY_OFFSET_FILE, /* Assume PE is stored as a file */
        PE_LOCATE_BY_OFFSET_BASE, /* Assume PE is loaded into the memory */
} PeLocateByOffset;

static inline const void* pe_section_header_data(const void *base, const PeSectionHeader *header, PeLocateByOffset location, size_t *ret_size) {
        assert(header);
        switch (location) {
        case PE_LOCATE_BY_OFFSET_FILE:
                if (ret_size)
                        *ret_size = header->SizeOfRawData;
                return (const uint8_t *) base + header->PointerToRawData;
        case PE_LOCATE_BY_OFFSET_BASE:
                if (ret_size)
                        *ret_size = header->VirtualSize;
                return (const uint8_t *) base + header->VirtualAddress;
        default:
                return NULL;
        }
}

static inline const void* pe_section_vector_data(const void *base, const PeSectionVector *entry, PeLocateByOffset location, size_t *ret_size) {
        assert(entry);
        switch (location) {
        case PE_LOCATE_BY_OFFSET_FILE:
                if (ret_size)
                        *ret_size = entry->file_size;
                return (const uint8_t *) base + entry->file_offset;
        case PE_LOCATE_BY_OFFSET_BASE:
                if (ret_size)
                        *ret_size = entry->memory_size;
                return (const uint8_t *) base + entry->memory_size;
        default:
                return NULL;
        }
}

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
                PeSectionVector sections[],
                PeLocateByOffset location);

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char *const section_names[],
                PeSectionVector sections[],
                PeLocateByOffset location);

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address, size_t *ret_size_in_memory);
