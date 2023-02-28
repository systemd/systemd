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

# pylint: disable=missing-docstring,invalid-name,attribute-defined-outside-init

import argparse
import hashlib
import io
import os
import pathlib
import time
from ctypes import (
    c_char,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    LittleEndianStructure,
    sizeof,
)

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile, Section as ELFSection
from elftools.elf.enums import (
    ENUM_DT_FLAGS_1,
    ENUM_RELOC_TYPE_AARCH64,
    ENUM_RELOC_TYPE_ARM,
    ENUM_RELOC_TYPE_i386,
    ENUM_RELOC_TYPE_x64,
)
from elftools.elf.relocation import (
    Relocation as ElfRelocation,
    RelocationTable as ElfRelocationTable,
)


class PeCoffHeader(LittleEndianStructure):
    _fields_ = (
        ("Machine", c_uint16),
        ("NumberOfSections", c_uint16),
        ("TimeDateStamp", c_uint32),
        ("PointerToSymbolTable", c_uint32),
        ("NumberOfSymbols", c_uint32),
        ("SizeOfOptionalHeader", c_uint16),
        ("Characteristics", c_uint16),
    )


class PeDataDirectory(LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", c_uint32),
        ("Size", c_uint32),
    )


class PeRelocationBlock(LittleEndianStructure):
    _fields_ = (
        ("PageRVA", c_uint32),
        ("BlockSize", c_uint32),
    )

    def __init__(self, PageRVA: int):
        super().__init__(PageRVA)
        self.entries: list[PeRelocationEntry] = []


class PeRelocationEntry(LittleEndianStructure):
    _fields_ = (
        ("Offset", c_uint16, 12),
        ("Type", c_uint16, 4),
    )


class PeOptionalHeaderStart(LittleEndianStructure):
    _fields_ = (
        ("Magic", c_uint16),
        ("MajorLinkerVersion", c_uint8),
        ("MinorLinkerVersion", c_uint8),
        ("SizeOfCode", c_uint32),
        ("SizeOfInitializedData", c_uint32),
        ("SizeOfUninitializedData", c_uint32),
        ("AddressOfEntryPoint", c_uint32),
        ("BaseOfCode", c_uint32),
    )


class PeOptionalHeaderMiddle(LittleEndianStructure):
    _fields_ = (
        ("SectionAlignment", c_uint32),
        ("FileAlignment", c_uint32),
        ("MajorOperatingSystemVersion", c_uint16),
        ("MinorOperatingSystemVersion", c_uint16),
        ("MajorImageVersion", c_uint16),
        ("MinorImageVersion", c_uint16),
        ("MajorSubsystemVersion", c_uint16),
        ("MinorSubsystemVersion", c_uint16),
        ("Win32VersionValue", c_uint32),
        ("SizeOfImage", c_uint32),
        ("SizeOfHeaders", c_uint32),
        ("CheckSum", c_uint32),
        ("Subsystem", c_uint16),
        ("DllCharacteristics", c_uint16),
    )


class PeOptionalHeaderEnd(LittleEndianStructure):
    _fields_ = (
        ("LoaderFlags", c_uint32),
        ("NumberOfRvaAndSizes", c_uint32),
        ("ExportTable", PeDataDirectory),
        ("ImportTable", PeDataDirectory),
        ("ResourceTable", PeDataDirectory),
        ("ExceptionTable", PeDataDirectory),
        ("CertificateTable", PeDataDirectory),
        ("BaseRelocationTable", PeDataDirectory),
        ("Debug", PeDataDirectory),
        ("Architecture", PeDataDirectory),
        ("GlobalPtr", PeDataDirectory),
        ("TLSTable", PeDataDirectory),
        ("LoadConfigTable", PeDataDirectory),
        ("BoundImport", PeDataDirectory),
        ("IAT", PeDataDirectory),
        ("DelayImportDescriptor", PeDataDirectory),
        ("CLRRuntimeHeader", PeDataDirectory),
        ("Reserved", PeDataDirectory),
    )


class PeOptionalHeader(LittleEndianStructure):
    pass


class PeOptionalHeader32(PeOptionalHeader):
    _anonymous_ = ("Start", "Middle", "End")
    _fields_ = (
        ("Start", PeOptionalHeaderStart),
        ("BaseOfData", c_uint32),
        ("ImageBase", c_uint32),
        ("Middle", PeOptionalHeaderMiddle),
        ("SizeOfStackReserve", c_uint32),
        ("SizeOfStackCommit", c_uint32),
        ("SizeOfHeapReserve", c_uint32),
        ("SizeOfHeapCommit", c_uint32),
        ("End", PeOptionalHeaderEnd),
    )


class PeOptionalHeader32Plus(PeOptionalHeader):
    _anonymous_ = ("Start", "Middle", "End")
    _fields_ = (
        ("Start", PeOptionalHeaderStart),
        ("ImageBase", c_uint64),
        ("Middle", PeOptionalHeaderMiddle),
        ("SizeOfStackReserve", c_uint64),
        ("SizeOfStackCommit", c_uint64),
        ("SizeOfHeapReserve", c_uint64),
        ("SizeOfHeapCommit", c_uint64),
        ("End", PeOptionalHeaderEnd),
    )


class PeSection(LittleEndianStructure):
    _fields_ = (
        ("Name", c_char * 8),
        ("VirtualSize", c_uint32),
        ("VirtualAddress", c_uint32),
        ("SizeOfRawData", c_uint32),
        ("PointerToRawData", c_uint32),
        ("PointerToRelocations", c_uint32),
        ("PointerToLinenumbers", c_uint32),
        ("NumberOfRelocations", c_uint16),
        ("NumberOfLinenumbers", c_uint16),
        ("Characteristics", c_uint32),
    )

    def __init__(self):
        super().__init__()
        self.data = bytearray()


N_DATA_DIRECTORY_ENTRIES = 16

assert sizeof(PeSection) == 40
assert sizeof(PeCoffHeader) == 20
assert sizeof(PeOptionalHeader32) == 224
assert sizeof(PeOptionalHeader32Plus) == 240

# EFI mandates 4KiB memory pages.
SECTION_ALIGNMENT = 4096
FILE_ALIGNMENT = 512

# Nobody cares about DOS headers, so put the PE header right after.
PE_OFFSET = 64


def align_to(x: int, align: int) -> int:
    return (x + align - 1) & ~(align - 1)


def use_section(elf_s: ELFSection) -> bool:
    # These sections are either needed during conversion to PE or are otherwise not needed
    # in the final PE image.
    IGNORE_SECTIONS = [
        ".ARM.exidx",
        ".dynamic",
        ".dynstr",
        ".dynsym",
        ".eh_frame_hdr",
        ".eh_frame",
        ".gnu.hash",
        ".hash",
        ".note.gnu.build-id",
        ".rel.dyn",
        ".rela.dyn",
    ]

    # Known sections we care about and want to be in the final PE.
    COPY_SECTIONS = [
        ".data",
        ".osrel",
        ".rodata",
        ".sbat",
        ".sdmagic",
        ".text",
    ]

    # By only dealing with allocating sections we effectively filter out debug sections.
    if not elf_s["sh_flags"] & SH_FLAGS.SHF_ALLOC:
        return False

    if elf_s.name in IGNORE_SECTIONS:
        return False

    # For paranoia we only handle sections we know of. Any new sections that come up should
    # be added to IGNORE_SECTIONS/COPY_SECTIONS and/or the linker script.
    if elf_s.name not in COPY_SECTIONS:
        raise RuntimeError(f"Unknown section {elf_s.name}, refusing.")

    if elf_s["sh_addr"] % SECTION_ALIGNMENT != 0:
        raise RuntimeError(f"Section {elf_s.name} is not aligned.")
    if len(elf_s.name) > 8:
        raise RuntimeError(f"ELF section name {elf_s.name} too long.")

    return True


def convert_elf_section(elf_s: ELFSection) -> PeSection:
    pe_s = PeSection()
    pe_s.Name = elf_s.name.encode()
    pe_s.VirtualSize = elf_s.data_size
    pe_s.VirtualAddress = elf_s["sh_addr"]
    pe_s.SizeOfRawData = align_to(elf_s.data_size, FILE_ALIGNMENT)
    pe_s.data = bytearray(elf_s.data())

    if elf_s["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
        pe_s.Characteristics = 0x60000020  # CNT_CODE|MEM_READ|MEM_EXECUTE
    elif elf_s["sh_flags"] & SH_FLAGS.SHF_WRITE:
        pe_s.Characteristics = 0xC0000040  # CNT_INITIALIZED_DATA|MEM_READ|MEM_WRITE
    else:
        pe_s.Characteristics = 0x40000040  # CNT_INITIALIZED_DATA|MEM_READ

    return pe_s


def copy_sections(elf: ELFFile, opt: PeOptionalHeader) -> list[PeSection]:
    sections = []

    for elf_s in elf.iter_sections():
        if not use_section(elf_s):
            continue

        pe_s = convert_elf_section(elf_s)
        if pe_s.Name == b".text":
            opt.BaseOfCode = pe_s.VirtualAddress
            opt.SizeOfCode += pe_s.VirtualSize
        else:
            opt.SizeOfInitializedData += pe_s.VirtualSize

        if pe_s.Name == b".data" and isinstance(opt, PeOptionalHeader32):
            opt.BaseOfData = pe_s.VirtualAddress

        sections.append(pe_s)

    return sections


def apply_elf_relative_relocation(
    reloc: ElfRelocation, image_base: int, sections: list[PeSection], addend_size: int
):
    # fmt: off
    [target] = [
        pe_s for pe_s in sections
        if pe_s.VirtualAddress <= reloc["r_offset"] < pe_s.VirtualAddress + len(pe_s.data)
    ]
    # fmt: on

    addend_offset = reloc["r_offset"] - target.VirtualAddress

    if reloc.is_RELA():
        addend = reloc["r_addend"]
    else:
        addend = target.data[addend_offset : addend_offset + addend_size]
        addend = int.from_bytes(addend, byteorder="little")

    # This currently assumes that the ELF file has an image base of 0.
    value = (image_base + addend).to_bytes(addend_size, byteorder="little")
    target.data[addend_offset : addend_offset + addend_size] = value


def convert_elf_reloc_table(
    elf: ELFFile,
    elf_reloc_table: ElfRelocationTable,
    image_base: int,
    sections: list[PeSection],
    pe_reloc_blocks: dict[int, PeRelocationBlock],
):
    NONE_RELOC = {
        "EM_386": ENUM_RELOC_TYPE_i386["R_386_NONE"],
        "EM_AARCH64": ENUM_RELOC_TYPE_AARCH64["R_AARCH64_NONE"],
        "EM_ARM": ENUM_RELOC_TYPE_ARM["R_ARM_NONE"],
        "EM_LOONGARCH": 0,
        "EM_RISCV": 0,
        "EM_X86_64": ENUM_RELOC_TYPE_x64["R_X86_64_NONE"],
    }[elf["e_machine"]]

    RELATIVE_RELOC = {
        "EM_386": ENUM_RELOC_TYPE_i386["R_386_RELATIVE"],
        "EM_AARCH64": ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"],
        "EM_ARM": ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"],
        "EM_LOONGARCH": 3,
        "EM_RISCV": 3,
        "EM_X86_64": ENUM_RELOC_TYPE_x64["R_X86_64_RELATIVE"],
    }[elf["e_machine"]]

    for reloc in elf_reloc_table.iter_relocations():
        if reloc["r_info_type"] == NONE_RELOC:
            continue

        if reloc["r_info_type"] == RELATIVE_RELOC:
            apply_elf_relative_relocation(
                reloc, image_base, sections, elf.elfclass // 8
            )

            # Now that the ELF relocation has been applied, we can create a PE relocation.
            block_rva = reloc["r_offset"] & ~0xFFF
            if block_rva not in pe_reloc_blocks:
                pe_reloc_blocks[block_rva] = PeRelocationBlock(block_rva)

            entry = PeRelocationEntry()
            entry.Offset = reloc["r_offset"] & 0xFFF
            # REL_BASED_HIGHLOW or REL_BASED_DIR64
            entry.Type = 3 if elf.elfclass == 32 else 10
            pe_reloc_blocks[block_rva].entries.append(entry)

            continue

        raise RuntimeError(f"Unsupported relocation {reloc}")


def convert_elf_relocations(
    elf: ELFFile, opt: PeOptionalHeader, sections: list[PeSection]
) -> PeSection:
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        raise RuntimeError("ELF .dynamic section is missing.")

    [flags_tag] = dynamic.iter_tags("DT_FLAGS_1")
    if not flags_tag["d_val"] & ENUM_DT_FLAGS_1["DF_1_PIE"]:
        raise RuntimeError("ELF file is not a PIE.")

    pe_reloc_blocks: dict[int, PeRelocationBlock] = {}
    for reloc_type, reloc_table in dynamic.get_relocation_tables().items():
        if reloc_type not in ["REL", "RELA"]:
            raise RuntimeError("Unsupported relocation type {elf_reloc_type}.")
        convert_elf_reloc_table(
            elf, reloc_table, opt.ImageBase, sections, pe_reloc_blocks
        )

    data = bytearray()
    for rva in sorted(pe_reloc_blocks):
        block = pe_reloc_blocks[rva]
        n_relocs = len(block.entries)

        # Each block must start on a 32-bit boundary. Because each entry is 16 bits
        # the len has to be even. We pad by adding a none relocation.
        if n_relocs % 2 != 0:
            n_relocs += 1
            block.entries.append(PeRelocationEntry())

        block.BlockSize = (
            sizeof(PeRelocationBlock) + sizeof(PeRelocationEntry) * n_relocs
        )
        data += block
        for entry in sorted(block.entries, key=lambda e: e.Offset):
            data += entry

    pe_reloc_s = PeSection()
    pe_reloc_s.Name = b".reloc"
    pe_reloc_s.data = data
    pe_reloc_s.VirtualSize = len(data)
    pe_reloc_s.SizeOfRawData = align_to(len(data), FILE_ALIGNMENT)
    pe_reloc_s.VirtualAddress = align_to(
        sections[-1].VirtualAddress + sections[-1].VirtualSize, SECTION_ALIGNMENT
    )
    # CNT_INITIALIZED_DATA|MEM_READ|MEM_DISCARDABLE
    pe_reloc_s.Characteristics = 0x42000040

    sections.append(pe_reloc_s)
    opt.SizeOfInitializedData += pe_reloc_s.VirtualSize
    return pe_reloc_s


def write_pe(
    file, coff: PeCoffHeader, opt: PeOptionalHeader, sections: list[PeSection]
):
    file.write(b"MZ")
    file.seek(0x3C, io.SEEK_SET)
    file.write(PE_OFFSET.to_bytes(2, byteorder="little"))
    file.seek(PE_OFFSET, io.SEEK_SET)
    file.write(b"PE\0\0")
    file.write(coff)
    file.write(opt)

    offset = opt.SizeOfHeaders
    for pe_s in sorted(sections, key=lambda s: s.VirtualAddress):
        if pe_s.VirtualAddress < opt.SizeOfHeaders:
            # Linker script should make sure this does not happen.
            raise RuntimeError(f"Section {pe_s.Name} overlapping PE headers.")

        pe_s.PointerToRawData = offset
        file.write(pe_s)
        offset = align_to(offset + len(pe_s.data), FILE_ALIGNMENT)

    for pe_s in sections:
        file.seek(pe_s.PointerToRawData, io.SEEK_SET)
        file.write(pe_s.data)

    file.truncate(offset)


def elf2efi(args: argparse.Namespace):
    elf = ELFFile(args.ELF)
    if not elf.little_endian:
        raise RuntimeError("ELF file is not little-endian.")
    if elf["e_type"] not in ["ET_DYN", "ET_EXEC"]:
        raise RuntimeError("Unsupported ELF type.")

    pe_arch = {
        "EM_386": 0x014C,
        "EM_AARCH64": 0xAA64,
        "EM_ARM": 0x01C2,
        "EM_LOONGARCH": 0x6232 if elf.elfclass == 32 else 0x6264,
        "EM_RISCV": 0x5032 if elf.elfclass == 32 else 0x5064,
        "EM_X86_64": 0x8664,
    }.get(elf["e_machine"])
    if pe_arch is None:
        raise RuntimeError(f"Unuspported ELF arch {elf['e_machine']}")

    coff = PeCoffHeader()
    opt = PeOptionalHeader32() if elf.elfclass == 32 else PeOptionalHeader32Plus()

    # We relocate to a unique image base to reduce the chances for runtime relocation to occur.
    base_name = pathlib.Path(args.PE.name).name.encode()
    opt.ImageBase = int(hashlib.sha1(base_name).hexdigest()[0:8], 16)
    if elf.elfclass == 32:
        opt.ImageBase = (0x400000 + opt.ImageBase) & 0xFFFF0000
    else:
        opt.ImageBase = (0x100000000 + opt.ImageBase) & 0x1FFFF0000

    sections = copy_sections(elf, opt)
    pe_reloc_s = convert_elf_relocations(elf, opt, sections)

    coff.Machine = pe_arch
    coff.NumberOfSections = len(sections)
    coff.TimeDateStamp = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    coff.SizeOfOptionalHeader = sizeof(opt)
    # EXECUTABLE_IMAGE|LINE_NUMS_STRIPPED|LOCAL_SYMS_STRIPPED|DEBUG_STRIPPED
    # and (32BIT_MACHINE or LARGE_ADDRESS_AWARE)
    coff.Characteristics = 0x30E if elf.elfclass == 32 else 0x22E

    opt.AddressOfEntryPoint = elf["e_entry"]
    opt.SectionAlignment = SECTION_ALIGNMENT
    opt.FileAlignment = FILE_ALIGNMENT
    opt.MajorImageVersion = args.version_major
    opt.MinorImageVersion = args.version_minor
    opt.MajorSubsystemVersion = args.efi_major
    opt.MinorSubsystemVersion = args.efi_minor
    opt.Subsystem = args.subsystem
    opt.Magic = 0x10B if elf.elfclass == 32 else 0x20B
    opt.SizeOfImage = align_to(
        sections[-1].VirtualAddress + sections[-1].VirtualSize, SECTION_ALIGNMENT
    )
    opt.SizeOfHeaders = align_to(
        PE_OFFSET
        + coff.SizeOfOptionalHeader
        + sizeof(PeSection) * coff.NumberOfSections,
        FILE_ALIGNMENT,
    )
    # DYNAMIC_BASE|NX_COMPAT|HIGH_ENTROPY_VA or DYNAMIC_BASE|NX_COMPAT
    opt.DllCharacteristics = 0x160 if elf.elfclass == 64 else 0x140

    # These values are taken from a natively built PE binary (although, unused by EDK2/EFI).
    opt.SizeOfStackReserve = 0x100000
    opt.SizeOfStackCommit = 0x001000
    opt.SizeOfHeapReserve = 0x100000
    opt.SizeOfHeapCommit = 0x001000

    opt.NumberOfRvaAndSizes = N_DATA_DIRECTORY_ENTRIES
    opt.BaseRelocationTable = PeDataDirectory(
        pe_reloc_s.VirtualAddress, pe_reloc_s.VirtualSize
    )

    write_pe(args.PE, coff, opt, sections)


def main():
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

    elf2efi(parser.parse_args())


if __name__ == "__main__":
    main()
