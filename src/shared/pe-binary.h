/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "openssl-util.h"
#include "macro-fundamental.h"
#include "sparse-endian.h"
#include "uki.h"

#define IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE 4U

/* When naming things we try to stay close to the official Windows APIs as per:
 * → https://learn.microsoft.com/en-us/windows/win32/debug/pe-format  */

typedef struct _packed_ _IMAGE_DOS_HEADER {
        le16_t e_magic;
        le16_t e_cblp;
        le16_t e_cp;
        le16_t e_crlc;
        le16_t e_cparhdr;
        le16_t e_minalloc;
        le16_t e_maxalloc;
        le16_t e_ss;
        le16_t e_sp;
        le16_t e_csum;
        le16_t e_ip;
        le16_t e_cs;
        le16_t e_lfarlc;
        le16_t e_ovno;
        le16_t e_res[4];
        le16_t e_oemid;
        le16_t e_oeminfo;
        le16_t e_res2[10];
        le32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _packed_ _IMAGE_FILE_HEADER {
        le16_t Machine;
        le16_t NumberOfSections;
        le32_t TimeDateStamp;
        le32_t PointerToSymbolTable;
        le32_t NumberOfSymbols;
        le16_t SizeOfOptionalHeader;
        le16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _packed_ _IMAGE_DATA_DIRECTORY {
        le32_t VirtualAddress;
        le32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _packed_ _IMAGE_OPTIONAL_HEADER {
        /* Standard fields */
        le16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        le32_t SizeOfCode;
        le32_t SizeOfInitializedData;
        le32_t SizeOfUninitializedData;
        le32_t AddressOfEntryPoint;
        le32_t BaseOfCode;

        /* Here the PE32 and PE32+ headers differ: PE32+ has one 64bit field, PE32+ has two 32bit fields */
        union {
                struct {
                        le32_t BaseOfData;
                        le32_t pe32_ImageBase;
                };
                le64_t pe32plus_ImageBase;
        };

        /* Additional fields */
        le32_t SectionAlignment;
        le32_t FileAlignment;
        le16_t MajorOperatingSystemVersion;
        le16_t MinorOperatingSystemVersion;
        le16_t MajorImageVersion;
        le16_t MinorImageVersion;
        le16_t MajorSubsystemVersion;
        le16_t MinorSubsystemVersion;
        le32_t Win32VersionValue;
        le32_t SizeOfImage;
        le32_t SizeOfHeaders;
        le32_t CheckSum;
        le16_t Subsystem;
        le16_t DllCharacteristics;

        /* Here similar: on PE32+ some fields are 64bit that are 32bit on PE32. */
        union {
                struct {
                        le32_t pe32_SizeOfStackReserve;
                        le32_t pe32_SizeOfStackCommit;
                        le32_t pe32_SizeOfHeapReserve;
                        le32_t pe32_SizeOfHeapCommit;
                        le32_t pe32_LoaderFlags;
                        le32_t pe32_NumberOfRvaAndSizes;
                        IMAGE_DATA_DIRECTORY pe32_DataDirectory[];
                };
                struct {
                        le64_t pe32plus_SizeOfStackReserve;
                        le64_t pe32plus_SizeOfStackCommit;
                        le64_t pe32plus_SizeOfHeapReserve;
                        le64_t pe32plus_SizeOfHeapCommit;
                        le32_t pe32plus_LoaderFlags;
                        le32_t pe32plus_NumberOfRvaAndSizes;
                        IMAGE_DATA_DIRECTORY pe32plus_DataDirectory[];
                };
        };
} IMAGE_OPTIONAL_HEADER;

typedef struct _packed_ PeHeader {
        le32_t signature;
        IMAGE_FILE_HEADER pe;
        IMAGE_OPTIONAL_HEADER optional;
} PeHeader;

typedef struct _packed_ _IMAGE_SECTION_HEADER {
        uint8_t Name[8];
        le32_t VirtualSize;
        le32_t VirtualAddress;
        le32_t SizeOfRawData;
        le32_t PointerToRawData;
        le32_t PointerToRelocations;
        le32_t PointerToLinenumbers;
        le16_t NumberOfRelocations;
        le16_t NumberOfLinenumbers;
        le32_t Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10

bool pe_header_is_64bit(const PeHeader *h);

#define PE_HEADER_OPTIONAL_FIELD(h, field)                           \
        (pe_header_is_64bit(h) ? (h)->optional.pe32plus_##field : (h)->optional.pe32_##field)

#define PE_HEADER_OPTIONAL_FIELD_OFFSET(h, field) \
        (pe_header_is_64bit(h) ? offsetof(PeHeader, optional.pe32plus_##field) : offsetof(PeHeader, optional.pe32_##field))

const IMAGE_DATA_DIRECTORY *pe_header_get_data_directory(const PeHeader *h, size_t i);
const IMAGE_SECTION_HEADER *pe_header_find_section(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections, const char *name);
const IMAGE_SECTION_HEADER *pe_section_table_find(const IMAGE_SECTION_HEADER *sections, size_t n_sections, const char *name);

int pe_load_headers(int fd, IMAGE_DOS_HEADER **ret_dos_header, PeHeader **ret_pe_header);

int pe_load_sections(int fd, const IMAGE_DOS_HEADER *dos_header, const PeHeader *pe_header, IMAGE_SECTION_HEADER **ret_sections);
int pe_read_section_data(int fd, const IMAGE_SECTION_HEADER *section, size_t max_size, void **ret, size_t *ret_size);
int pe_read_section_data_by_name(int fd, const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections, const char *name, size_t max_size, void **ret, size_t *ret_size);

bool pe_is_uki(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections);
bool pe_is_addon(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections);

bool pe_is_native(const PeHeader *pe_header);

int pe_hash(int fd, const EVP_MD *md, void **ret_hash, size_t *ret_hash_size);

int pe_checksum(int fd, uint32_t *ret);

int uki_hash(int fd, const EVP_MD *md, void *ret_hashes[static _UNIFIED_SECTION_MAX], size_t *ret_hash_size);
