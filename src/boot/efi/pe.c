/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "pe.h"
#include "util.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"
#define MAX_SECTIONS 96

#if defined(__i386__)
        #define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_IA32
#elif defined(__x86_64__)
        #define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_X64
#elif defined(__aarch64__)
        #define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_AARCH64
#elif defined(__arm__)
        #define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_ARMTHUMB_MIXED
#elif defined(__riscv) && __riscv_xlen == 64
        #define TARGET_MACHINE_TYPE EFI_IMAGE_MACHINE_RISCV64
#else
        #error Unknown EFI arch
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

struct PeFileHeader {
        UINT8   Magic[4];
        struct CoffFileHeader FileHeader;
        /* OptionalHeader omitted */
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
        return CompareMem(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0;
}

static inline BOOLEAN verify_pe(const struct PeFileHeader *pe) {
        assert(pe);
        return CompareMem(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) == 0 &&
               pe->FileHeader.Machine == TARGET_MACHINE_TYPE &&
               pe->FileHeader.NumberOfSections > 0 &&
               pe->FileHeader.NumberOfSections <= MAX_SECTIONS;
}

static inline UINTN section_table_offset(const struct DosFileHeader *dos, const struct PeFileHeader *pe) {
        assert(dos);
        assert(pe);
        return dos->ExeHeader + sizeof(struct PeFileHeader) + pe->FileHeader.SizeOfOptionalHeader;
}

static VOID locate_sections(
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
                        if (CompareMem(sect->Name, sections[j], strlena(sections[j])) != 0)
                                continue;

                        if (addrs)
                                addrs[j] = sect->VirtualAddress;
                        if (offsets)
                                offsets[j] = sect->PointerToRawData;
                        sizes[j] = sect->VirtualSize;
                }
        }
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
        if (!verify_pe(pe))
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
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        struct DosFileHeader dos;
        struct PeFileHeader pe;
        UINTN len, section_table_len;
        EFI_STATUS err;

        assert(dir);
        assert(path);
        assert(sections);
        assert(offsets);
        assert(sizes);

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, (CHAR16*)path, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        len = sizeof(dos);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &dos);
        if (EFI_ERROR(err))
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(handle->SetPosition, 2, handle, dos.ExeHeader);
        if (EFI_ERROR(err))
                return err;

        len = sizeof(pe);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &pe);
        if (EFI_ERROR(err))
                return err;
        if (len != sizeof(pe) || !verify_pe(&pe))
                return EFI_LOAD_ERROR;

        section_table_len = pe.FileHeader.NumberOfSections * sizeof(struct PeSectionHeader);
        section_table = AllocatePool(section_table_len);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = uefi_call_wrapper(handle->SetPosition, 2, handle, section_table_offset(&dos, &pe));
        if (EFI_ERROR(err))
                return err;

        len = section_table_len;
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, section_table);
        if (EFI_ERROR(err))
                return err;
        if (len != section_table_len)
                return EFI_LOAD_ERROR;

        locate_sections(section_table, pe.FileHeader.NumberOfSections,
                        sections, NULL, offsets, sizes);

        return EFI_SUCCESS;
}
