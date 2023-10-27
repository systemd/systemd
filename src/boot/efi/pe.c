/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe.h"
#include "uki.h"
#include "util.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"
#define MAX_SECTIONS 96

#if defined(__i386__)
#  define TARGET_MACHINE_TYPE 0x014CU
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0x8664U
#elif defined(__x86_64__)
#  define TARGET_MACHINE_TYPE 0x8664U
#elif defined(__aarch64__)
#  define TARGET_MACHINE_TYPE 0xAA64U
#elif defined(__arm__)
#  define TARGET_MACHINE_TYPE 0x01C2U
#elif defined(__riscv) && __riscv_xlen == 32
#  define TARGET_MACHINE_TYPE 0x5032U
#elif defined(__riscv) && __riscv_xlen == 64
#  define TARGET_MACHINE_TYPE 0x5064U
#elif defined(__loongarch__) && __loongarch_grlen == 32
#  define TARGET_MACHINE_TYPE 0x6232U
#elif defined(__loongarch__) && __loongarch_grlen == 64
#  define TARGET_MACHINE_TYPE 0x6264U
#else
#  error Unknown EFI arch
#endif

#ifndef TARGET_MACHINE_TYPE_COMPATIBILITY
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0
#endif

typedef struct DosFileHeader {
        uint8_t  Magic[2];
        uint16_t LastSize;
        uint16_t nBlocks;
        uint16_t nReloc;
        uint16_t HdrSize;
        uint16_t MinAlloc;
        uint16_t MaxAlloc;
        uint16_t ss;
        uint16_t sp;
        uint16_t Checksum;
        uint16_t ip;
        uint16_t cs;
        uint16_t RelocPos;
        uint16_t nOverlay;
        uint16_t reserved[4];
        uint16_t OEMId;
        uint16_t OEMInfo;
        uint16_t reserved2[10];
        uint32_t ExeHeader;
} _packed_ DosFileHeader;

typedef struct CoffFileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
} _packed_ CoffFileHeader;

#define OPTHDR32_MAGIC 0x10B /* PE32  OptionalHeader */
#define OPTHDR64_MAGIC 0x20B /* PE32+ OptionalHeader */

typedef struct PeOptionalHeader {
        uint16_t Magic;
        uint8_t  LinkerMajor;
        uint8_t  LinkerMinor;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializeData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        union {
                struct { /* PE32 */
                        uint32_t BaseOfData;
                        uint32_t ImageBase32;
                };
                uint64_t ImageBase64; /* PE32+ */
        };
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        /* fields with different sizes for 32/64 omitted */
} _packed_ PeOptionalHeader;

typedef struct PeFileHeader {
        uint8_t   Magic[4];
        CoffFileHeader FileHeader;
        PeOptionalHeader OptionalHeader;
} _packed_ PeFileHeader;

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

static bool verify_dos(const DosFileHeader *dos) {
        assert(dos);
        return memcmp(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0;
}

static bool verify_pe(const PeFileHeader *pe, bool allow_compatibility) {
        assert(pe);
        return memcmp(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) == 0 &&
               (pe->FileHeader.Machine == TARGET_MACHINE_TYPE ||
                (allow_compatibility && pe->FileHeader.Machine == TARGET_MACHINE_TYPE_COMPATIBILITY)) &&
               pe->FileHeader.NumberOfSections > 0 &&
               pe->FileHeader.NumberOfSections <= MAX_SECTIONS &&
               IN_SET(pe->OptionalHeader.Magic, OPTHDR32_MAGIC, OPTHDR64_MAGIC);
}

static size_t section_table_offset(const DosFileHeader *dos, const PeFileHeader *pe) {
        assert(dos);
        assert(pe);
        return dos->ExeHeader + offsetof(PeFileHeader, OptionalHeader) + pe->FileHeader.SizeOfOptionalHeader;
}

static ssize_t locate_section(
                const PeSectionHeader section_table[],
                size_t n_table,
                const char *section_name,
                size_t *ret_offset,
                size_t *ret_size,
                bool in_memory) {

        assert(section_table);
        assert(section_name);
        assert(ret_offset);
        assert(ret_size);

        for (size_t i = 0; i < n_table; i++) {
                const PeSectionHeader *sect = section_table + i;

                if (memcmp(sect->Name, section_name, strlen8(section_name)) != 0)
                        continue;

                *ret_offset = in_memory ? sect->VirtualAddress : sect->PointerToRawData;
                *ret_size = sect->VirtualSize;
                return i;
        }

        return -1;
}

static uint32_t get_compatibility_entry_address(const DosFileHeader *dos, const PeFileHeader *pe) {
        size_t addr = 0, size = 0;

        /* The kernel may provide alternative PE entry points for different PE architectures. This allows
         * booting a 64-bit kernel on 32-bit EFI that is otherwise running on a 64-bit CPU. The locations of any
         * such compat entry points are located in a special PE section. */

        ssize_t idx = locate_section(
                (const PeSectionHeader *) ((const uint8_t *) dos + section_table_offset(dos, pe)),
                pe->FileHeader.NumberOfSections,
                ".compat",
                &addr,
                &size,
                /*in_memory=*/true);

        if (idx < 0)
                return 0;

        typedef struct {
                uint8_t type;
                uint8_t size;
                uint16_t machine_type;
                uint32_t entry_point;
        } _packed_ LinuxPeCompat1;

        while (size >= sizeof(LinuxPeCompat1) && addr % alignof(LinuxPeCompat1) == 0) {
                LinuxPeCompat1 *compat = (LinuxPeCompat1 *) ((uint8_t *) dos + addr);

                if (compat->type == 0 || compat->size == 0 || compat->size > size)
                        break;

                if (compat->type == 1 &&
                    compat->size >= sizeof(LinuxPeCompat1) &&
                    compat->machine_type == TARGET_MACHINE_TYPE)
                        return compat->entry_point;

                addr += compat->size;
                size -= compat->size;
        }

        return 0;
}

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address) {
        assert(base);
        assert(ret_compat_address);

        const DosFileHeader *dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        /* Support for LINUX_INITRD_MEDIA_GUID was added in kernel stub 1.0. */
        if (pe->OptionalHeader.MajorImageVersion < 1)
                return EFI_UNSUPPORTED;

        if (pe->FileHeader.Machine == TARGET_MACHINE_TYPE) {
                *ret_compat_address = 0;
                return EFI_SUCCESS;
        }

        uint32_t compat_address = get_compatibility_entry_address(dos, pe);
        if (compat_address == 0)
                /* Image type not supported and no compat entry found. */
                return EFI_UNSUPPORTED;

        *ret_compat_address = compat_address;
        return EFI_SUCCESS;
}

static int compare_section_descriptors(const PeSectionDescriptor *a, const PeSectionDescriptor *b) {
        return strcmp8(a->name, b->name);
}

static void locate_sections(
                const PeSectionHeader section_table[],
                size_t n_table,
                PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections,
                bool in_memory) {

        assert(section_table);
        assert(ret_sections);
        assert(ret_n_sections);

        *ret_sections = xmalloc_multiply(sizeof **ret_sections, n_table);
        *ret_n_sections = 0;

        for (const PeSectionHeader *section_hdr = section_table; section_hdr < section_table + n_table; ++section_hdr) {
                PeSectionDescriptor *desc = *ret_sections + (*ret_n_sections)++;
                memcpy(desc->name, section_hdr->Name, sizeof section_hdr->Name);
                desc->name[sizeof section_hdr->Name] = 0;
                desc->offset = in_memory ? section_hdr->VirtualAddress : section_hdr->PointerToRawData;
                desc->size = section_hdr->VirtualSize;
        }

        /* Sort section descriptors */
        sort_array(*ret_sections, sizeof **ret_sections, *ret_n_sections, (compare_func_t) compare_section_descriptors);
}

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections) {
        const DosFileHeader *dos;
        const PeFileHeader *pe;
        size_t offset;

        assert(base);
        assert(ret_sections);
        assert(ret_n_sections);

        dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (const PeFileHeader *) ((uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        offset = section_table_offset(dos, pe);
        locate_sections((PeSectionHeader *) ((uint8_t *) base + offset),
                        pe->FileHeader.NumberOfSections,
                        ret_sections,
                        ret_n_sections,
                        /*in_memory=*/true);

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                PeSectionDescriptor **ret_sections,
                size_t *ret_n_sections) {
        _cleanup_free_ PeSectionHeader *section_table = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        DosFileHeader dos;
        PeFileHeader pe;
        size_t len, section_table_len;
        EFI_STATUS err;

        assert(dir);
        assert(path);
        assert(ret_sections);
        assert(ret_n_sections);

        err = dir->Open(dir, &handle, (char16_t *) path, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return err;

        len = sizeof(dos);
        err = handle->Read(handle, &len, &dos);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = handle->SetPosition(handle, dos.ExeHeader);
        if (err != EFI_SUCCESS)
                return err;

        len = sizeof(pe);
        err = handle->Read(handle, &len, &pe);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(pe) || !verify_pe(&pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        section_table_len = pe.FileHeader.NumberOfSections * sizeof(PeSectionHeader);
        section_table = xmalloc(section_table_len);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = handle->SetPosition(handle, section_table_offset(&dos, &pe));
        if (err != EFI_SUCCESS)
                return err;

        len = section_table_len;
        err = handle->Read(handle, &len, section_table);
        if (err != EFI_SUCCESS)
                return err;
        if (len != section_table_len)
                return EFI_LOAD_ERROR;

        locate_sections(section_table, pe.FileHeader.NumberOfSections,
                        ret_sections, ret_n_sections, /*in_memory=*/false);

        return EFI_SUCCESS;
}

static int compare_section_descriptor_with_key(const PeSectionDescriptor *desc, const char *key) {
        return strcmp8(desc->name, key);
}

PeSectionDescriptor *pe_find_section(PeSectionDescriptor *sections, size_t n_sections, const char *section_name) {
        return bsearch_array(section_name, sections, sizeof *sections, n_sections, (compare_func_t) compare_section_descriptor_with_key);
}

PeSectionDescriptor *pe_find_unified_section(PeSectionDescriptor *sections, size_t n_sections, UnifiedSection unified_section) {
        return bsearch_array(unified_sections[unified_section], sections, sizeof *sections, n_sections, (compare_func_t) compare_section_descriptor_with_key);
}