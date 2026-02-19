#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# Convert ELF static PIE to PE/EFI image.

# To do so we simply copy desired ELF sections while preserving their memory layout to ensure that
# code still runs as expected. We then translate ELF relocations to PE relocations so that the EFI
# loader/firmware can properly load the binary to any address at runtime.
#
# To make this as painless as possible we only operate on static PIEs as they should only contain
# base relocations that are easy to handle as they have a one-to-one mapping to PE relocations.
#
# EDK2 does a similar process using their GenFw tool. The main difference is that they use the
# --emit-relocs linker flag, which emits a lot of different (static) ELF relocation types that have
# to be handled differently for each architecture and is overall more work than its worth.
#
# Note that on arches where binutils has PE support (x86/x86_64 mostly, aarch64 only recently)
# objcopy can be used to convert ELF to PE. But this will still not convert ELF relocations, making
# the resulting binary useless. gnu-efi relies on this method and contains a stub that performs the
# ELF dynamic relocations at runtime.

# pylint: disable=attribute-defined-outside-init
# mypy: untyped-calls-exclude=elftools

import argparse
import hashlib
import io
import os
import pathlib
import sys
import time
import typing
from ctypes import (
    c_char,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    LittleEndianStructure,
    sizeof,
)

from elftools import elf
from elftools.elf import elffile


class PeCoffHeader(LittleEndianStructure):
    _fields_ = (
        ("Machine",              c_uint16),
        ("NumberOfSections",     c_uint16),
        ("TimeDateStamp",        c_uint32),
        ("PointerToSymbolTable", c_uint32),
        ("NumberOfSymbols",      c_uint32),
        ("SizeOfOptionalHeader", c_uint16),
        ("Characteristics",      c_uint16),
    )


class PeDataDirectory(LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", c_uint32),
        ("Size",           c_uint32),
    )


class PeRelocationBlock(LittleEndianStructure):
    _fields_ = (
        ("PageRVA",   c_uint32),
        ("BlockSize", c_uint32),
    )

    def __init__(self, PageRVA: int):
        super().__init__(PageRVA)
        self.entries: list[PeRelocationEntry] = []


class PeRelocationEntry(LittleEndianStructure):
    _fields_ = (
        ("Offset", c_uint16, 12),
        ("Type",   c_uint16, 4),
    )


class PeOptionalHeaderStart(LittleEndianStructure):
    _fields_ = (
        ("Magic",                   c_uint16),
        ("MajorLinkerVersion",      c_uint8),
        ("MinorLinkerVersion",      c_uint8),
        ("SizeOfCode",              c_uint32),
        ("SizeOfInitializedData",   c_uint32),
        ("SizeOfUninitializedData", c_uint32),
        ("AddressOfEntryPoint",     c_uint32),
        ("BaseOfCode",              c_uint32),
    )


class PeOptionalHeaderMiddle(LittleEndianStructure):
    _fields_ = (
        ("SectionAlignment",            c_uint32),
        ("FileAlignment",               c_uint32),
        ("MajorOperatingSystemVersion", c_uint16),
        ("MinorOperatingSystemVersion", c_uint16),
        ("MajorImageVersion",           c_uint16),
        ("MinorImageVersion",           c_uint16),
        ("MajorSubsystemVersion",       c_uint16),
        ("MinorSubsystemVersion",       c_uint16),
        ("Win32VersionValue",           c_uint32),
        ("SizeOfImage",                 c_uint32),
        ("SizeOfHeaders",               c_uint32),
        ("CheckSum",                    c_uint32),
        ("Subsystem",                   c_uint16),
        ("DllCharacteristics",          c_uint16),
    )


class PeOptionalHeaderEnd(LittleEndianStructure):
    _fields_ = (
        ("LoaderFlags",           c_uint32),
        ("NumberOfRvaAndSizes",   c_uint32),
        ("ExportTable",           PeDataDirectory),
        ("ImportTable",           PeDataDirectory),
        ("ResourceTable",         PeDataDirectory),
        ("ExceptionTable",        PeDataDirectory),
        ("CertificateTable",      PeDataDirectory),
        ("BaseRelocationTable",   PeDataDirectory),
        ("Debug",                 PeDataDirectory),
        ("Architecture",          PeDataDirectory),
        ("GlobalPtr",             PeDataDirectory),
        ("TLSTable",              PeDataDirectory),
        ("LoadConfigTable",       PeDataDirectory),
        ("BoundImport",           PeDataDirectory),
        ("IAT",                   PeDataDirectory),
        ("DelayImportDescriptor", PeDataDirectory),
        ("CLRRuntimeHeader",      PeDataDirectory),
        ("Reserved",              PeDataDirectory),
    )


class PeOptionalHeader(LittleEndianStructure):
    pass


class PeOptionalHeader32(PeOptionalHeader):
    _anonymous_ = ("Start", "Middle", "End")
    _fields_ = (
        ("Start",              PeOptionalHeaderStart),
        ("BaseOfData",         c_uint32),
        ("ImageBase",          c_uint32),
        ("Middle",             PeOptionalHeaderMiddle),
        ("SizeOfStackReserve", c_uint32),
        ("SizeOfStackCommit",  c_uint32),
        ("SizeOfHeapReserve",  c_uint32),
        ("SizeOfHeapCommit",   c_uint32),
        ("End",                PeOptionalHeaderEnd),
    )


class PeOptionalHeader32Plus(PeOptionalHeader):
    _anonymous_ = ("Start", "Middle", "End")
    _fields_ = (
        ("Start",              PeOptionalHeaderStart),
        ("ImageBase",          c_uint64),
        ("Middle",             PeOptionalHeaderMiddle),
        ("SizeOfStackReserve", c_uint64),
        ("SizeOfStackCommit",  c_uint64),
        ("SizeOfHeapReserve",  c_uint64),
        ("SizeOfHeapCommit",   c_uint64),
        ("End",                PeOptionalHeaderEnd),
    )


class PeSection(LittleEndianStructure):
    _fields_ = (
        ("Name",                 c_char * 8),
        ("VirtualSize",          c_uint32),
        ("VirtualAddress",       c_uint32),
        ("SizeOfRawData",        c_uint32),
        ("PointerToRawData",     c_uint32),
        ("PointerToRelocations", c_uint32),
        ("PointerToLinenumbers", c_uint32),
        ("NumberOfRelocations",  c_uint16),
        ("NumberOfLinenumbers",  c_uint16),
        ("Characteristics",      c_uint32),
    )

    def __init__(self) -> None:
        super().__init__()
        self.data = bytearray()


N_DATA_DIRECTORY_ENTRIES = 16

assert sizeof(PeSection) == 40
assert sizeof(PeCoffHeader) == 20
assert sizeof(PeOptionalHeader32) == 224
assert sizeof(PeOptionalHeader32Plus) == 240

PE_CHARACTERISTICS_RX = 0x60000020  # CNT_CODE|MEM_READ|MEM_EXECUTE
PE_CHARACTERISTICS_RW = 0xC0000040  # CNT_INITIALIZED_DATA|MEM_READ|MEM_WRITE
PE_CHARACTERISTICS_R  = 0x40000040  # CNT_INITIALIZED_DATA|MEM_READ

IGNORE_SECTIONS = [
    ".eh_frame",
    ".eh_frame_hdr",
    ".ARM.exidx",
    ".relro_padding",
    ".sframe",
]

IGNORE_SECTION_TYPES = [
    "SHT_DYNAMIC",
    "SHT_DYNSYM",
    "SHT_GNU_ATTRIBUTES",
    "SHT_GNU_HASH",
    "SHT_HASH",
    "SHT_NOTE",
    "SHT_REL",
    "SHT_RELA",
    "SHT_RELR",
    "SHT_STRTAB",
    "SHT_SYMTAB",
]

# EFI mandates 4KiB memory pages.
SECTION_ALIGNMENT = 4096
FILE_ALIGNMENT = 512

# Nobody cares about DOS headers, so put the PE header right after.
PE_OFFSET = 64
PE_MAGIC = b"PE\0\0"


def align_to(x: int, align: int) -> int:
    return (x + align - 1) & ~(align - 1)


def align_down(x: int, align: int) -> int:
    return x & ~(align - 1)


def next_section_address(sections: list[PeSection]) -> int:
    return align_to(sections[-1].VirtualAddress + sections[-1].VirtualSize,
                    SECTION_ALIGNMENT)


class BadSectionError(ValueError):
    "One of the sections is in a bad state"


def iter_copy_sections(file: elffile.ELFFile) -> typing.Iterator[PeSection]:
    pe_s = None

    # This is essentially the same as copying by ELF load segments, except that we assemble them
    # manually, so that we can easily strip unwanted sections. We try to only discard things we know
    # about so that there are no surprises.

    relro = None
    for elf_seg in file.iter_segments():
        if elf_seg["p_type"] == "PT_LOAD" and elf_seg["p_align"] != SECTION_ALIGNMENT:
            raise BadSectionError(f"ELF segment {elf_seg['p_type']} is not properly aligned"
                                  f" ({elf_seg['p_align']} != {SECTION_ALIGNMENT})")
        if elf_seg["p_type"] == "PT_GNU_RELRO":
            relro = elf_seg

    for elf_s in file.iter_sections():
        if (
            elf_s["sh_flags"] & elf.constants.SH_FLAGS.SHF_ALLOC == 0
            or elf_s["sh_type"] in IGNORE_SECTION_TYPES
            or elf_s.name in IGNORE_SECTIONS
            or elf_s["sh_size"] == 0
        ):
            continue
        if elf_s["sh_type"] not in ["SHT_PROGBITS", "SHT_NOBITS"]:
            raise BadSectionError(f"Unknown section {elf_s.name} with type {elf_s['sh_type']}")
        if elf_s.name == '.got':
            # FIXME: figure out why those sections are inserted
            print("WARNING: Non-empty .got section", file=sys.stderr)

        if elf_s["sh_flags"] & elf.constants.SH_FLAGS.SHF_EXECINSTR:
            rwx = PE_CHARACTERISTICS_RX
        elif elf_s["sh_flags"] & elf.constants.SH_FLAGS.SHF_WRITE:
            rwx = PE_CHARACTERISTICS_RW
        else:
            rwx = PE_CHARACTERISTICS_R

        # PE images are always relro.
        if relro and relro.section_in_segment(elf_s):
            rwx = PE_CHARACTERISTICS_R

        if pe_s and pe_s.Characteristics != rwx:
            yield pe_s
            pe_s = None

        if pe_s:
            # Insert padding to properly align the section.
            pad_len = elf_s["sh_addr"] - pe_s.VirtualAddress - len(pe_s.data)
            pe_s.data += bytearray(pad_len) + elf_s.data()
        else:
            pe_s = PeSection()
            pe_s.VirtualAddress = elf_s["sh_addr"]
            pe_s.Characteristics = rwx
            pe_s.data = elf_s.data()

    if pe_s:
        yield pe_s


def convert_sections(
        file: elffile.ELFFile,
        opt: PeOptionalHeader,
) -> list[PeSection]:
    last_vma = (0, 0)
    sections = []

    for pe_s in iter_copy_sections(file):
        # Truncate the VMA to the nearest page and insert appropriate padding. This should not
        # cause any overlap as this is pretty much how ELF *segments* are loaded/mmapped anyways.
        # The ELF sections inside should also be properly aligned as we reuse the ELF VMA layout
        # for the PE image.
        vma = pe_s.VirtualAddress
        pe_s.VirtualAddress = align_down(vma, SECTION_ALIGNMENT)
        pe_s.data = bytearray(vma - pe_s.VirtualAddress) + pe_s.data

        pe_s.VirtualSize = len(pe_s.data)
        pe_s.SizeOfRawData = align_to(len(pe_s.data), FILE_ALIGNMENT)
        pe_s.Name = {
            PE_CHARACTERISTICS_RX: b".text",
            PE_CHARACTERISTICS_RW: b".data",
            PE_CHARACTERISTICS_R: b".rodata",
        }[pe_s.Characteristics]

        # This can happen if not building with '-z separate-code'.
        if pe_s.VirtualAddress < sum(last_vma):
            raise BadSectionError(f"Section {pe_s.Name.decode()!r} @0x{pe_s.VirtualAddress:x} overlaps"
                                  f" previous section @0x{last_vma[0]:x}+0x{last_vma[1]:x}=@0x{sum(last_vma):x}")
        last_vma = (pe_s.VirtualAddress, pe_s.VirtualSize)

        if pe_s.Name == b".text":
            opt.BaseOfCode = pe_s.VirtualAddress
            opt.SizeOfCode += pe_s.VirtualSize
        else:
            opt.SizeOfInitializedData += pe_s.VirtualSize

        if pe_s.Name == b".data" and isinstance(opt, PeOptionalHeader32):
            opt.BaseOfData = pe_s.VirtualAddress

        sections.append(pe_s)

    return sections


def copy_sections(
    file: elffile.ELFFile,
    opt: PeOptionalHeader,
    input_names: str,
    sections: list[PeSection],
) -> None:
    for name in input_names.split(","):
        elf_s = file.get_section_by_name(name)
        if not elf_s:
            continue
        if elf_s.data_alignment > 1 and SECTION_ALIGNMENT % elf_s.data_alignment != 0:
            raise BadSectionError(f"ELF section {name} is not aligned")
        if elf_s["sh_flags"] & (elf.constants.SH_FLAGS.SHF_EXECINSTR | elf.constants.SH_FLAGS.SHF_WRITE) != 0:
            raise BadSectionError(f"ELF section {name} is not read-only data")

        pe_s = PeSection()
        pe_s.Name = name.encode()
        pe_s.data = elf_s.data()
        pe_s.VirtualAddress = next_section_address(sections)
        pe_s.VirtualSize = len(elf_s.data())
        pe_s.SizeOfRawData = align_to(len(elf_s.data()), FILE_ALIGNMENT)
        pe_s.Characteristics = PE_CHARACTERISTICS_R
        opt.SizeOfInitializedData += pe_s.VirtualSize
        sections.append(pe_s)


def apply_elf_relative_relocation(
    reloc: elf.relocation.Relocation,
    image_base: int,
    sections: list[PeSection],
    addend_size: int,
) -> None:
    [target] = [pe_s for pe_s in sections
                if pe_s.VirtualAddress <= reloc["r_offset"] < pe_s.VirtualAddress + len(pe_s.data)]

    addend_offset = reloc["r_offset"] - target.VirtualAddress

    if reloc.is_RELA():
        addend = reloc["r_addend"]
    else:
        addend = target.data[addend_offset : addend_offset + addend_size]
        addend = int.from_bytes(addend, byteorder="little")

    value = (image_base + addend).to_bytes(addend_size, byteorder="little")
    target.data[addend_offset : addend_offset + addend_size] = value


def convert_elf_reloc_table(
    file: elffile.ELFFile,
    elf_reloc_table: elf.relocation.RelocationTable,
    elf_image_base: int,
    sections: list[PeSection],
    pe_reloc_blocks: dict[int, PeRelocationBlock],
) -> None:
    NONE_RELOC = {
        "EM_386":       elf.enums.ENUM_RELOC_TYPE_i386["R_386_NONE"],
        "EM_AARCH64":   elf.enums.ENUM_RELOC_TYPE_AARCH64["R_AARCH64_NONE"],
        "EM_ARM":       elf.enums.ENUM_RELOC_TYPE_ARM["R_ARM_NONE"],
        "EM_LOONGARCH": 0,
        "EM_RISCV":     0,
        "EM_X86_64":    elf.enums.ENUM_RELOC_TYPE_x64["R_X86_64_NONE"],
    }[file["e_machine"]]

    RELATIVE_RELOC = {
        "EM_386":       elf.enums.ENUM_RELOC_TYPE_i386["R_386_RELATIVE"],
        "EM_AARCH64":   elf.enums.ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"],
        "EM_ARM":       elf.enums.ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"],
        "EM_LOONGARCH": 3,
        "EM_RISCV":     3,
        "EM_X86_64":    elf.enums.ENUM_RELOC_TYPE_x64["R_X86_64_RELATIVE"],
    }[file["e_machine"]]

    for reloc in elf_reloc_table.iter_relocations():
        if reloc["r_info_type"] == NONE_RELOC:
            continue

        if reloc["r_info_type"] == RELATIVE_RELOC:
            apply_elf_relative_relocation(reloc,
                                          elf_image_base,
                                          sections,
                                          file.elfclass // 8)

            # Now that the ELF relocation has been applied, we can create a PE relocation.
            block_rva = reloc["r_offset"] & ~0xFFF
            if block_rva not in pe_reloc_blocks:
                pe_reloc_blocks[block_rva] = PeRelocationBlock(block_rva)

            entry = PeRelocationEntry()
            entry.Offset = reloc["r_offset"] & 0xFFF
            # REL_BASED_HIGHLOW or REL_BASED_DIR64
            entry.Type = 3 if file.elfclass == 32 else 10
            pe_reloc_blocks[block_rva].entries.append(entry)

            continue

        raise BadSectionError(f"Unsupported relocation {reloc}")


def convert_elf_relocations(
    file: elffile.ELFFile,
    opt: PeOptionalHeader,
    sections: list[PeSection],
    minimum_sections: int,
) -> typing.Optional[PeSection]:
    dynamic = file.get_section_by_name(".dynamic")
    if dynamic is None:
        raise BadSectionError("ELF .dynamic section is missing")

    [flags_tag] = dynamic.iter_tags("DT_FLAGS_1")
    if not flags_tag["d_val"] & elf.enums.ENUM_DT_FLAGS_1["DF_1_PIE"]:
        raise ValueError("ELF file is not a PIE")

    # This checks that the ELF image base is 0.
    symtab = file.get_section_by_name(".symtab")
    if symtab:
        exe_start = symtab.get_symbol_by_name("__executable_start")
        if exe_start and exe_start[0]["st_value"] != 0:
            raise ValueError("Unexpected ELF image base")

    opt.SizeOfHeaders = align_to(PE_OFFSET
                                 + len(PE_MAGIC)
                                 + sizeof(PeCoffHeader)
                                 + sizeof(opt)
                                 + sizeof(PeSection) * max(len(sections) + 1, minimum_sections),
                                 FILE_ALIGNMENT)

    # We use the basic VMA layout from the ELF image in the PE image. This could cause the first
    # section to overlap the PE image headers during runtime at VMA 0. We can simply apply a fixed
    # offset relative to the PE image base when applying/converting ELF relocations. Afterwards we
    # just have to apply the offset to the PE addresses so that the PE relocations work correctly on
    # the ELF portions of the image.
    segment_offset = 0
    if sections[0].VirtualAddress < opt.SizeOfHeaders:
        segment_offset = align_to(opt.SizeOfHeaders - sections[0].VirtualAddress,
                                  SECTION_ALIGNMENT)

    opt.AddressOfEntryPoint = file["e_entry"] + segment_offset
    opt.BaseOfCode += segment_offset
    if isinstance(opt, PeOptionalHeader32):
        opt.BaseOfData += segment_offset

    pe_reloc_blocks: dict[int, PeRelocationBlock] = {}
    for reloc_type, reloc_table in dynamic.get_relocation_tables().items():
        if reloc_type not in ["REL", "RELA"]:
            raise BadSectionError(f"Unsupported relocation type {reloc_type}")
        convert_elf_reloc_table(file,
                                reloc_table,
                                opt.ImageBase + segment_offset,
                                sections,
                                pe_reloc_blocks)

    for pe_s in sections:
        pe_s.VirtualAddress += segment_offset

    if len(pe_reloc_blocks) == 0:
        return None

    data = bytearray()
    for rva in sorted(pe_reloc_blocks):
        block = pe_reloc_blocks[rva]
        n_relocs = len(block.entries)

        # Each block must start on a 32-bit boundary. Because each entry is 16 bits
        # the len has to be even. We pad by adding a none relocation.
        if n_relocs % 2 != 0:
            n_relocs += 1
            block.entries.append(PeRelocationEntry())

        block.PageRVA += segment_offset
        block.BlockSize = sizeof(PeRelocationBlock) + sizeof(PeRelocationEntry) * n_relocs
        data += block
        for entry in sorted(block.entries, key=lambda e: e.Offset):
            data += entry

    pe_reloc_s = PeSection()
    pe_reloc_s.Name = b".reloc"
    pe_reloc_s.data = data
    pe_reloc_s.VirtualAddress = next_section_address(sections)
    pe_reloc_s.VirtualSize = len(data)
    pe_reloc_s.SizeOfRawData = align_to(len(data), FILE_ALIGNMENT)
    # CNT_INITIALIZED_DATA|MEM_READ|MEM_DISCARDABLE
    pe_reloc_s.Characteristics = 0x42000040

    sections.append(pe_reloc_s)
    opt.SizeOfInitializedData += pe_reloc_s.VirtualSize
    return pe_reloc_s


def write_pe(
    file: typing.IO[bytes],
    coff: PeCoffHeader,
    opt: PeOptionalHeader,
    sections: list[PeSection],
) -> None:
    file.write(b"MZ")
    file.seek(0x3C, io.SEEK_SET)
    file.write(PE_OFFSET.to_bytes(2, byteorder="little"))
    file.seek(PE_OFFSET, io.SEEK_SET)
    file.write(PE_MAGIC)
    file.write(coff)
    file.write(opt)

    offset = opt.SizeOfHeaders
    for pe_s in sorted(sections, key=lambda s: s.VirtualAddress):
        if pe_s.VirtualAddress < opt.SizeOfHeaders:
            raise BadSectionError(f"Section {pe_s.Name} @0x{pe_s.VirtualAddress:x} overlaps"
                                  " PE headers ending at 0x{opt.SizeOfHeaders:x}")

        pe_s.PointerToRawData = offset
        file.write(pe_s)
        offset = align_to(offset + len(pe_s.data), FILE_ALIGNMENT)

    assert file.tell() <= opt.SizeOfHeaders

    for pe_s in sections:
        file.seek(pe_s.PointerToRawData, io.SEEK_SET)
        file.write(pe_s.data)

    file.truncate(offset)


def elf2efi(args: argparse.Namespace) -> None:
    file = elffile.ELFFile(args.ELF)
    if not file.little_endian:
        raise ValueError("ELF file is not little-endian")
    if file["e_type"] not in ["ET_DYN", "ET_EXEC"]:
        raise ValueError(f"Unsupported ELF type {file['e_type']}")

    pe_arch = {
        "EM_386": 0x014C,
        "EM_AARCH64": 0xAA64,
        "EM_ARM": 0x01C2,
        "EM_LOONGARCH": 0x6232 if file.elfclass == 32 else 0x6264,
        "EM_RISCV": 0x5032 if file.elfclass == 32 else 0x5064,
        "EM_X86_64": 0x8664,
    }.get(file["e_machine"])
    if pe_arch is None:
        raise ValueError(f"Unsupported ELF architecture {file['e_machine']}")

    coff = PeCoffHeader()
    opt = PeOptionalHeader32() if file.elfclass == 32 else PeOptionalHeader32Plus()

    # We relocate to a unique image base to reduce the chances for runtime relocation to occur.
    base_name = pathlib.Path(args.PE.name).name.encode()
    opt.ImageBase = int(hashlib.sha1(base_name).hexdigest()[0:8], 16)
    if file.elfclass == 32:
        opt.ImageBase = (0x400000 + opt.ImageBase) & 0xFFFF0000
    else:
        opt.ImageBase = (0x100000000 + opt.ImageBase) & 0x1FFFF0000

    sections = convert_sections(file, opt)
    copy_sections(file, opt, args.copy_sections, sections)
    pe_reloc_s = convert_elf_relocations(file, opt, sections, args.minimum_sections)

    coff.Machine = pe_arch
    coff.NumberOfSections = len(sections)
    coff.TimeDateStamp = int(os.environ.get("SOURCE_DATE_EPOCH") or time.time())
    coff.SizeOfOptionalHeader = sizeof(opt)
    # EXECUTABLE_IMAGE|LINE_NUMS_STRIPPED|LOCAL_SYMS_STRIPPED|DEBUG_STRIPPED
    # and (32BIT_MACHINE or LARGE_ADDRESS_AWARE)
    coff.Characteristics = 0x30E if file.elfclass == 32 else 0x22E

    opt.SectionAlignment = SECTION_ALIGNMENT
    opt.FileAlignment = FILE_ALIGNMENT
    opt.MajorImageVersion = args.version_major
    opt.MinorImageVersion = args.version_minor
    opt.MajorSubsystemVersion = args.efi_major
    opt.MinorSubsystemVersion = args.efi_minor
    opt.Subsystem = args.subsystem
    opt.Magic = 0x10B if file.elfclass == 32 else 0x20B
    opt.SizeOfImage = next_section_address(sections)

    # DYNAMIC_BASE|NX_COMPAT|HIGH_ENTROPY_VA or DYNAMIC_BASE|NX_COMPAT
    opt.DllCharacteristics = 0x160 if file.elfclass == 64 else 0x140

    # These values are taken from a natively built PE binary (although, unused by EDK2/EFI).
    opt.SizeOfStackReserve = 0x100000
    opt.SizeOfStackCommit = 0x001000
    opt.SizeOfHeapReserve = 0x100000
    opt.SizeOfHeapCommit = 0x001000

    opt.NumberOfRvaAndSizes = N_DATA_DIRECTORY_ENTRIES
    if pe_reloc_s:
        opt.BaseRelocationTable = PeDataDirectory(
            pe_reloc_s.VirtualAddress, pe_reloc_s.VirtualSize
        )

    write_pe(args.PE, coff, opt, sections)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert ELF binaries to PE/EFI")
    parser.add_argument(
        "--version-major",
        type=int,
        default=0,
        help="Major image version of EFI image",
    )
    parser.add_argument(
        "--version-minor",
        type=int,
        default=0,
        help="Minor image version of EFI image",
    )
    parser.add_argument(
        "--efi-major",
        type=int,
        default=0,
        help="Minimum major EFI subsystem version",
    )
    parser.add_argument(
        "--efi-minor",
        type=int,
        default=0,
        help="Minimum minor EFI subsystem version",
    )
    parser.add_argument(
        "--subsystem",
        type=int,
        default=10,
        help="PE subsystem",
    )
    parser.add_argument(
        "ELF",
        type=argparse.FileType("rb"),
        help="Input ELF file",
    )
    parser.add_argument(
        "PE",
        type=argparse.FileType("wb"),
        help="Output PE/EFI file",
    )
    parser.add_argument(
        "--minimum-sections",
        type=int,
        default=0,
        help="Minimum number of sections to leave space for",
    )
    parser.add_argument(
        "--copy-sections",
        type=str,
        default="",
        help="Copy these sections if found",
    )
    return parser


def main() -> None:
    parser = create_parser()
    elf2efi(parser.parse_args())


if __name__ == "__main__":
    main()
