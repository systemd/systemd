/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>
#include <pe.h>

#include "pe.h"
#include "util.h"

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

static inline BOOLEAN verify_dos(const IMAGE_DOS_HEADER *dos) {
        assert(dos);
        return dos->e_magic == IMAGE_DOS_SIGNATURE;
}

static inline BOOLEAN verify_pe(const IMAGE_NT_HEADERS *pe) {
        assert(pe);
        return pe->Signature == IMAGE_NT_SIGNATURE &&
               pe->FileHeader.Machine == TARGET_MACHINE_TYPE &&
               pe->FileHeader.NumberOfSections > 0 &&
               pe->FileHeader.NumberOfSections <= MAX_SECTIONS;
}

static inline UINTN section_table_offset(const IMAGE_DOS_HEADER *dos, const IMAGE_NT_HEADERS *pe) {
        assert(dos);
        assert(pe);
        return dos->e_lfanew +
               OFFSETOF(IMAGE_NT_HEADERS, OptionalHeader) +
               pe->FileHeader.SizeOfOptionalHeader;
}

static VOID locate_sections(
                const IMAGE_SECTION_HEADER section_table[],
                UINTN n_table,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *offsets,
                UINTN *sizes) {

        assert(section_table);
        assert(sections);
        assert(sizes);

        for (UINTN i = 0; i < n_table; i++) {
                const IMAGE_SECTION_HEADER *sect = &section_table[i];

                for (UINTN j = 0; sections[j]; j++) {
                        /* If section name length is exactly 8, the name is *not* null terminated!. */
                        if (strncmpa(sect->Name, sections[j], ELEMENTSOF(sect->Name)) != 0)
                                continue;

                        if (addrs)
                                addrs[j] = sect->VirtualAddress;
                        if (offsets)
                                offsets[j] = sect->PointerToRawData;
                        sizes[j] = sect->Misc.VirtualSize;
                }
        }
}

EFI_STATUS pe_memory_locate_sections(
                const CHAR8 *base,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *offsets,
                UINTN *sizes) {
        IMAGE_DOS_HEADER *dos;
        IMAGE_NT_HEADERS *pe;
        UINTN offset;

        assert(base);
        assert(sections);
        assert(sizes);

        dos = (IMAGE_DOS_HEADER*)base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (IMAGE_NT_HEADERS*)&base[dos->e_lfanew];
        if (!verify_pe(pe))
                return EFI_LOAD_ERROR;

        offset = section_table_offset(dos, pe);
        locate_sections((IMAGE_SECTION_HEADER*)&base[offset], pe->FileHeader.NumberOfSections,
                        sections, addrs, offsets, sizes);

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const CHAR16 *path,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *offsets,
                UINTN *sizes) {
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS pe;
        UINTN len, section_table_len;
        EFI_STATUS err;
        _cleanup_freepool_ IMAGE_SECTION_HEADER *section_table = NULL;

        assert(dir);
        assert(path);
        assert(sections);
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

        err = uefi_call_wrapper(handle->SetPosition, 2, handle, dos.e_lfanew);
        if (EFI_ERROR(err))
                return err;

        len = sizeof(pe);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &pe);
        if (EFI_ERROR(err))
                return err;
        if (len != sizeof(pe) || !verify_pe(&pe))
                return EFI_LOAD_ERROR;

        section_table_len = pe.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
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
                        sections, addrs, offsets, sizes);

        return EFI_SUCCESS;
}
