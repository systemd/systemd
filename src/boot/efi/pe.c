/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "missing_efi.h"
#include "pe.h"
#include "util.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"
#define MAX_SECTIONS 96

#if defined(__i386__)
#  define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_IA32
#  define TARGET_MACHINE_TYPE_COMPATIBILITY EFI_IMAGE_MACHINE_X64
#elif defined(__x86_64__)
#  define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_X64
#elif defined(__aarch64__)
#  define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_AARCH64
#elif defined(__arm__)
#  define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_ARMTHUMB_MIXED
#elif defined(__riscv) && __riscv_xlen == 64
#  define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_RISCV64
#else
#  error Unknown EFI arch
#endif

#ifndef TARGET_MACHINE_TYPE_COMPATIBILITY
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0
#endif

struct DosFileHeader {
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
} _packed_;

struct CoffFileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
} _packed_;

#define OPTHDR32_MAGIC 0x10B /* PE32  OptionalHeader */
#define OPTHDR64_MAGIC 0x20B /* PE32+ OptionalHeader */

struct PeOptionalHeader {
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
} _packed_;

struct PeFileHeader {
        uint8_t   Magic[4];
        struct CoffFileHeader FileHeader;
        struct PeOptionalHeader OptionalHeader;
} _packed_;

struct PeSectionHeader {
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
} _packed_;

static inline bool verify_dos(const struct DosFileHeader *dos) {
        assert(dos);
        return memcmp(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0;
}

static inline bool verify_pe(const struct PeFileHeader *pe, bool allow_compatibility) {
        assert(pe);
        return memcmp(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) == 0 &&
               (pe->FileHeader.Machine == TARGET_MACHINE_TYPE ||
                (allow_compatibility && pe->FileHeader.Machine == TARGET_MACHINE_TYPE_COMPATIBILITY)) &&
               pe->FileHeader.NumberOfSections > 0 &&
               pe->FileHeader.NumberOfSections <= MAX_SECTIONS &&
               IN_SET(pe->OptionalHeader.Magic, OPTHDR32_MAGIC, OPTHDR64_MAGIC);
}

static inline UINTN section_table_offset(const struct DosFileHeader *dos, const struct PeFileHeader *pe) {
        assert(dos);
        assert(pe);
        return dos->ExeHeader + offsetof(struct PeFileHeader, OptionalHeader) + pe->FileHeader.SizeOfOptionalHeader;
}

static void locate_sections(
                const struct PeSectionHeader section_table[],
                UINTN n_table,
                const char **sections,
                UINTN *addrs,
                UINTN *offsets,
                UINTN *sizes) {

        assert(section_table);
        assert(sections);
        assert(sizes);

        for (UINTN i = 0; i < n_table; i++) {
                const struct PeSectionHeader *sect = section_table + i;

                for (UINTN j = 0; sections[j]; j++) {
                        if (memcmp(sect->Name, sections[j], strlen8(sections[j])) != 0)
                                continue;

                        if (addrs)
                                addrs[j] = sect->VirtualAddress;
                        if (offsets)
                                offsets[j] = sect->PointerToRawData;
                        sizes[j] = sect->VirtualSize;
                }
        }
}

static uint32_t get_compatibility_entry_address(const struct DosFileHeader *dos, const struct PeFileHeader *pe) {
        UINTN addr = 0, size = 0;
        static const char *sections[] = { ".compat", NULL };

        /* The kernel may provide alternative PE entry points for different PE architectures. This allows
         * booting a 64bit kernel on 32bit EFI that is otherwise running on a 64bit CPU. The locations of any
         * such compat entry points are located in a special PE section. */

        locate_sections((const struct PeSectionHeader *) ((const uint8_t *) dos + section_table_offset(dos, pe)),
                        pe->FileHeader.NumberOfSections,
                        sections,
                        &addr,
                        NULL,
                        &size);

        if (size == 0)
                return 0;

        typedef struct {
                uint8_t type;
                uint8_t size;
                uint16_t machine_type;
                uint32_t entry_point;
        } _packed_ LinuxPeCompat1;

        while (size >= sizeof(LinuxPeCompat1) && addr % __alignof__(LinuxPeCompat1) == 0) {
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

EFI_STATUS pe_alignment_info(
                const void *base,
                uint32_t *ret_entry_point_address,
                uint32_t *ret_size_of_image,
                uint32_t *ret_section_alignment) {

        const struct DosFileHeader *dos;
        const struct PeFileHeader *pe;

        assert(base);
        assert(ret_entry_point_address);

        dos = (const struct DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (const struct PeFileHeader*) ((const uint8_t *)base + dos->ExeHeader);
        if (!verify_pe(pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        uint32_t entry_address = pe->OptionalHeader.AddressOfEntryPoint;

        /* Look for a compat entry point. */
        if (pe->FileHeader.Machine != TARGET_MACHINE_TYPE) {
                entry_address = get_compatibility_entry_address(dos, pe);
                if (entry_address == 0)
                        /* Image type not supported and no compat entry found. */
                        return EFI_UNSUPPORTED;
        }

        *ret_entry_point_address = entry_address;
        if (ret_size_of_image)
                *ret_size_of_image = pe->OptionalHeader.SizeOfImage;
        if (ret_section_alignment)
                *ret_section_alignment = pe->OptionalHeader.SectionAlignment;
        return EFI_SUCCESS;
}

EFI_STATUS pe_memory_locate_sections(
                const char *base,
                const char **sections,
                UINTN *addrs,
                UINTN *sizes) {
        const struct DosFileHeader *dos;
        const struct PeFileHeader *pe;
        UINTN offset;

        assert(base);
        assert(sections);
        assert(addrs);
        assert(sizes);

        dos = (const struct DosFileHeader*)base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (const struct PeFileHeader*)&base[dos->ExeHeader];
        if (!verify_pe(pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        offset = section_table_offset(dos, pe);
        locate_sections((struct PeSectionHeader*)&base[offset], pe->FileHeader.NumberOfSections,
                        sections, addrs, NULL, sizes);

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                const char **sections,
                UINTN *offsets,
                UINTN *sizes) {
        _cleanup_freepool_ struct PeSectionHeader *section_table = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        struct DosFileHeader dos;
        struct PeFileHeader pe;
        UINTN len, section_table_len;
        EFI_STATUS err;

        assert(dir);
        assert(path);
        assert(sections);
        assert(offsets);
        assert(sizes);

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

        section_table_len = pe.FileHeader.NumberOfSections * sizeof(struct PeSectionHeader);
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
                        sections, NULL, offsets, sizes);

        return EFI_SUCCESS;
}
