/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 */

#include <efi.h>
#include <efilib.h>

#include "pe.h"
#include "util.h"

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
} __attribute__((packed));

#define PE_HEADER_MACHINE_I386          0x014c
#define PE_HEADER_MACHINE_X64           0x8664
struct PeFileHeader {
        UINT16  Machine;
        UINT16  NumberOfSections;
        UINT32  TimeDateStamp;
        UINT32  PointerToSymbolTable;
        UINT32  NumberOfSymbols;
        UINT16  SizeOfOptionalHeader;
        UINT16  Characteristics;
} __attribute__((packed));

struct PeHeader {
        UINT8   Magic[4];
        struct PeFileHeader FileHeader;
} __attribute__((packed));

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
} __attribute__((packed));

EFI_STATUS pe_memory_locate_sections(CHAR8 *base, CHAR8 **sections, UINTN *addrs, UINTN *offsets, UINTN *sizes) {
        struct DosFileHeader *dos;
        struct PeHeader *pe;
        UINTN i;
        UINTN offset;

        dos = (struct DosFileHeader *)base;

        if (CompareMem(dos->Magic, "MZ", 2) != 0)
                return EFI_LOAD_ERROR;

        pe = (struct PeHeader *)&base[dos->ExeHeader];
        if (CompareMem(pe->Magic, "PE\0\0", 4) != 0)
                return EFI_LOAD_ERROR;

        /* PE32+ Subsystem type */
        if (pe->FileHeader.Machine != PE_HEADER_MACHINE_X64 &&
            pe->FileHeader.Machine != PE_HEADER_MACHINE_I386)
                return EFI_LOAD_ERROR;

        if (pe->FileHeader.NumberOfSections > 96)
                return EFI_LOAD_ERROR;

        offset = dos->ExeHeader + sizeof(*pe) + pe->FileHeader.SizeOfOptionalHeader;

        for (i = 0; i < pe->FileHeader.NumberOfSections; i++) {
                struct PeSectionHeader *sect;
                UINTN j;

                sect = (struct PeSectionHeader *)&base[offset];
                for (j = 0; sections[j]; j++) {
                        if (CompareMem(sect->Name, sections[j], strlena(sections[j])) != 0)
                                continue;

                        if (addrs)
                                addrs[j] = (UINTN)sect->VirtualAddress;
                        if (offsets)
                                offsets[j] = (UINTN)sect->PointerToRawData;
                        if (sizes)
                                sizes[j] = (UINTN)sect->VirtualSize;
                }
                offset += sizeof(*sect);
        }

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(EFI_FILE *dir, CHAR16 *path, CHAR8 **sections, UINTN *addrs, UINTN *offsets, UINTN *sizes) {
        EFI_FILE_HANDLE handle;
        struct DosFileHeader dos;
        struct PeHeader pe;
        UINTN len;
        UINTN headerlen;
        EFI_STATUS err;
        CHAR8 *header = NULL;

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, path, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        /* MS-DOS stub */
        len = sizeof(dos);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &dos);
        if (EFI_ERROR(err))
                goto out;
        if (len != sizeof(dos)) {
                err = EFI_LOAD_ERROR;
                goto out;
        }

        err = uefi_call_wrapper(handle->SetPosition, 2, handle, dos.ExeHeader);
        if (EFI_ERROR(err))
                goto out;

        len = sizeof(pe);
        err = uefi_call_wrapper(handle->Read, 3, handle, &len, &pe);
        if (EFI_ERROR(err))
                goto out;
        if (len != sizeof(pe)) {
                err = EFI_LOAD_ERROR;
                goto out;
        }

        headerlen = sizeof(dos) + sizeof(pe) + pe.FileHeader.SizeOfOptionalHeader + pe.FileHeader.NumberOfSections * sizeof(struct PeSectionHeader);
        header = AllocatePool(headerlen);
        if (!header) {
                err = EFI_OUT_OF_RESOURCES;
                goto out;
        }
        len = headerlen;
        err = uefi_call_wrapper(handle->SetPosition, 2, handle, 0);
        if (EFI_ERROR(err))
                goto out;

        err = uefi_call_wrapper(handle->Read, 3, handle, &len, header);
        if (EFI_ERROR(err)) {
                goto out;
        }
        if (len != headerlen) {
                err = EFI_LOAD_ERROR;
                goto out;
        }

        err = pe_memory_locate_sections(header, sections, addrs, offsets, sizes);
out:
        if (header)
                FreePool(header);
        uefi_call_wrapper(handle->Close, 1, handle);
        return err;
}
