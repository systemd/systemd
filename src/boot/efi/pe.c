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
        UINT8   Magic[2];
        UINT16  LastSize;
        UINT16  nBlocks;
        UINT16  nReloc;
        UINT16  HdrSize;
        UINT16  MinAlloc;
        UINT16  MaxAlloc;
        UINT16  ss;
        UINT16  sp;
        UINT16  Checksum;
        UINT16  ip;
        UINT16  cs;
        UINT16  RelocPos;
        UINT16  nOverlay;
        UINT16  reserved[4];
        UINT16  OEMId;
        UINT16  OEMInfo;
        UINT16  reserved2[10];
        UINT32  ExeHeader;
} _packed_;

struct CoffFileHeader {
        UINT16  Machine;
        UINT16  NumberOfSections;
        UINT32  TimeDateStamp;
        UINT32  PointerToSymbolTable;
        UINT32  NumberOfSymbols;
        UINT16  SizeOfOptionalHeader;
        UINT16  Characteristics;
} _packed_;

#define OPTHDR32_MAGIC 0x10B /* PE32  OptionalHeader */
#define OPTHDR64_MAGIC 0x20B /* PE32+ OptionalHeader */

struct PeOptionalHeader {
        UINT16  Magic;
        UINT8   LinkerMajor;
        UINT8   LinkerMinor;
        UINT32  SizeOfCode;
        UINT32  SizeOfInitializedData;
        UINT32  SizeOfUninitializeData;
        UINT32  AddressOfEntryPoint;
        UINT32  BaseOfCode;
        union {
                struct { /* PE32 */
                        UINT32 BaseOfData;
                        UINT32 ImageBase32;
                };
                UINT64 ImageBase64; /* PE32+ */
        };
        UINT32 SectionAlignment;
        UINT32 FileAlignment;
        UINT16 MajorOperatingSystemVersion;
        UINT16 MinorOperatingSystemVersion;
        UINT16 MajorImageVersion;
        UINT16 MinorImageVersion;
        UINT16 MajorSubsystemVersion;
        UINT16 MinorSubsystemVersion;
        UINT32 Win32VersionValue;
        UINT32 SizeOfImage;
        UINT32 SizeOfHeaders;
        UINT32 CheckSum;
        UINT16 Subsystem;
        UINT16 DllCharacteristics;
        /* fields with different sizes for 32/64 omitted */
} _packed_;

struct PeFileHeader {
        UINT8   Magic[4];
        struct CoffFileHeader FileHeader;
        struct PeOptionalHeader OptionalHeader;
} _packed_;

struct PeSectionHeader {
        UINT8   Name[8];
        UINT32  VirtualSize;
        UINT32  VirtualAddress;
        UINT32  SizeOfRawData;
        UINT32  PointerToRawData;
        UINT32  PointerToRelocations;
        UINT32  PointerToLinenumbers;
        UINT16  NumberOfRelocations;
        UINT16  NumberOfLinenumbers;
        UINT32  Characteristics;
} _packed_;

static inline BOOLEAN verify_dos(const struct DosFileHeader *dos) {
        assert(dos);
        return memcmp(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0;
}

static inline BOOLEAN verify_pe(const struct PeFileHeader *pe, BOOLEAN allow_compatibility) {
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
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *offsets,
                UINTN *sizes) {

        assert(section_table);
        assert(sections);
        assert(sizes);

        for (UINTN i = 0; i < n_table; i++) {
                const struct PeSectionHeader *sect = section_table + i;

                for (UINTN j = 0; sections[j]; j++) {
                        if (memcmp(sect->Name, sections[j], strlen8((const char *) sections[j])) != 0)
                                continue;

                        if (addrs)
                                addrs[j] = sect->VirtualAddress;
                        if (offsets)
                                offsets[j] = sect->PointerToRawData;
                        sizes[j] = sect->VirtualSize;
                }
        }
}

static UINT32 get_compatibility_entry_address(const struct DosFileHeader *dos, const struct PeFileHeader *pe) {
        UINTN addr = 0, size = 0;
        static const CHAR8 *sections[] = { (CHAR8 *) ".compat", NULL };

        /* The kernel may provide alternative PE entry points for different PE architectures. This allows
         * booting a 64bit kernel on 32bit EFI that is otherwise running on a 64bit CPU. The locations of any
         * such compat entry points are located in a special PE section. */

        locate_sections((const struct PeSectionHeader *) ((const UINT8 *) dos + section_table_offset(dos, pe)),
                        pe->FileHeader.NumberOfSections,
                        sections,
                        &addr,
                        NULL,
                        &size);

        if (size == 0)
                return 0;

        typedef struct {
                UINT8 type;
                UINT8 size;
                UINT16 machine_type;
                UINT32 entry_point;
        } _packed_ LinuxPeCompat1;

        while (size >= sizeof(LinuxPeCompat1) && addr % __alignof__(LinuxPeCompat1) == 0) {
                LinuxPeCompat1 *compat = (LinuxPeCompat1 *) ((UINT8 *) dos + addr);

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
                UINT32 *ret_entry_point_address,
                UINT32 *ret_size_of_image,
                UINT32 *ret_section_alignment) {

        const struct DosFileHeader *dos;
        const struct PeFileHeader *pe;

        assert(base);
        assert(ret_entry_point_address);

        dos = (const struct DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (const struct PeFileHeader*) ((const UINT8 *)base + dos->ExeHeader);
        if (!verify_pe(pe, /* allow_compatibility= */ TRUE))
                return EFI_LOAD_ERROR;

        UINT32 entry_address = pe->OptionalHeader.AddressOfEntryPoint;

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
                const CHAR8 *base,
                const CHAR8 **sections,
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
        if (!verify_pe(pe, /* allow_compatibility= */ FALSE))
                return EFI_LOAD_ERROR;

        offset = section_table_offset(dos, pe);
        locate_sections((struct PeSectionHeader*)&base[offset], pe->FileHeader.NumberOfSections,
                        sections, addrs, NULL, sizes);

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const CHAR16 *path,
                const CHAR8 **sections,
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

        err = dir->Open(dir, &handle, (CHAR16*)path, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        len = sizeof(dos);
        err = handle->Read(handle, &len, &dos);
        if (EFI_ERROR(err))
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = handle->SetPosition(handle, dos.ExeHeader);
        if (EFI_ERROR(err))
                return err;

        len = sizeof(pe);
        err = handle->Read(handle, &len, &pe);
        if (EFI_ERROR(err))
                return err;
        if (len != sizeof(pe) || !verify_pe(&pe, /* allow_compatibility= */ FALSE))
                return EFI_LOAD_ERROR;

        section_table_len = pe.FileHeader.NumberOfSections * sizeof(struct PeSectionHeader);
        section_table = xallocate_pool(section_table_len);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = handle->SetPosition(handle, section_table_offset(&dos, &pe));
        if (EFI_ERROR(err))
                return err;

        len = section_table_len;
        err = handle->Read(handle, &len, section_table);
        if (EFI_ERROR(err))
                return err;
        if (len != section_table_len)
                return EFI_LOAD_ERROR;

        locate_sections(section_table, pe.FileHeader.NumberOfSections,
                        sections, NULL, offsets, sizes);

        return EFI_SUCCESS;
}
