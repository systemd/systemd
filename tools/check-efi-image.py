#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: set tw=110 sw=4 ts=4 et:

import ctypes
import re
import sys

try:
    import elf2efi
    import pefile
    from elftools.elf import elffile
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SIZEOF_SYMBOL = 18


def get_string_table(pe):
    if pe.FILE_HEADER.PointerToSymbolTable > 0:
        coff_string_table_offset = (
            pe.FILE_HEADER.PointerToSymbolTable + IMAGE_SIZEOF_SYMBOL * pe.FILE_HEADER.NumberOfSymbols
        )
        return bytes(pe.__data__[coff_string_table_offset:])
    return None


def resolve_section_name(name, string_table):
    raw = name.rstrip(b'\x00')
    if not raw.startswith(b'/'):
        return raw.decode()

    if not string_table:
        raise ValueError(f'Indirect section name {raw} but PE has no COFF string table')

    if len(string_table) < 4:
        raise ValueError('COFF string table has invalid size')

    offset_raw = raw[1:]
    if not offset_raw.isdigit():
        raise ValueError(f'Section name {raw} is not a valid string table offset')

    offset = int(offset_raw)
    table_size = int.from_bytes(string_table[:4], 'little')
    if not 4 <= offset < table_size:
        raise ValueError(f'COFF string table offset {offset} out of bounds')

    if (end := string_table.find(b'\x00', offset, table_size)) == -1:
        raise ValueError(f'COFF string table entry at offset {offset} is not NUL-terminated')

    return string_table[offset:end].decode()


def check_debug_sections(elf_file, pe_names):
    elf_dwarf_names = {s.name for s in elf_file.iter_sections()}.intersection(elf2efi.DWARF_SECTION_NAMES)
    if not elf_dwarf_names.issubset(pe_names):
        print(
            f'DWARF sections in ELF but missing (or misresolved) in PE: '
            f'{sorted(elf_dwarf_names.difference(pe_names))}',
            file=sys.stderr,
        )
        sys.exit(1)


def get_elf_build_id(elf_file):
    section = elf_file.get_section_by_name('.note.gnu.build-id')
    if section is None:
        return None
    for note in section.iter_notes():
        if note['n_type'] == 'NT_GNU_BUILD_ID' and note['n_name'] == 'GNU':
            return note['n_descdata']
    return None


def check_build_id(pe, elf_path, elf_file):
    build_id = get_elf_build_id(elf_file)
    debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]

    if build_id is None or len(build_id) != 16:
        if debug_dir.VirtualAddress != 0:
            print(f'{elf_path} has no usable build-id, but PE has a debug directory anyway', file=sys.stderr)
            sys.exit(1)
        print(f'{elf_path} has no usable build-id, skipping CodeView checks', file=sys.stderr)
        return

    if debug_dir.VirtualAddress == 0:
        print('ELF has a build-id but PE has no debug directory', file=sys.stderr)
        sys.exit(1)

    entry_size = ctypes.sizeof(elf2efi.PeDebugDirectoryEntry)
    if debug_dir.Size != entry_size:
        print(
            f'Expected exactly one debug directory entry ({entry_size} bytes), found Size {debug_dir.Size}',
            file=sys.stderr,
        )
        sys.exit(1)

    base_offset = pe.get_offset_from_rva(debug_dir.VirtualAddress)
    entry = elf2efi.PeDebugDirectoryEntry.from_buffer_copy(pe.__data__, base_offset)

    if entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW:
        print(
            f'Expected debug directory entry of type CodeView ({IMAGE_DEBUG_TYPE_CODEVIEW}), '
            f'found {entry.Type}',
            file=sys.stderr,
        )
        sys.exit(1)

    raw_data_rva, raw_data_file_offset = entry.AddressOfRawData, entry.PointerToRawData

    if raw_data_rva != 0 and raw_data_file_offset != pe.get_offset_from_rva(raw_data_rva):
        print(
            f'Debug directory entry file offset {raw_data_file_offset:#x} does not match '
            f'RVA {raw_data_rva:#x}',
            file=sys.stderr,
        )
        sys.exit(1)

    record = elf2efi.PeCodeViewPdb70.from_buffer_copy(pe.__data__, raw_data_file_offset)
    if record.CvSignature != elf2efi.CV_INFO_PDB70_SIGNATURE:
        print(f'Expected RSDS CodeView signature, found {record.CvSignature!r}', file=sys.stderr)
        sys.exit(1)

    print(f'CodeView GUID: {bytes(record.Signature).hex()}')


def check_header_reserve(pe, expected_extra_sections):
    section_header_size = ctypes.sizeof(elf2efi.PeSection)
    end_of_section_table = pe.sections[-1].get_file_offset() + section_header_size
    free_slots = (pe.OPTIONAL_HEADER.SizeOfHeaders - end_of_section_table) // section_header_size
    if free_slots < expected_extra_sections:
        print(
            f'Only {free_slots} free section header slot(s), expected room for '
            f'{expected_extra_sections} extra section(s)',
            file=sys.stderr,
        )
        sys.exit(1)


def check_initialized_data_size(pe):
    initialized_data_size = sum(
        section.Misc_VirtualSize
        for section in pe.sections
        if section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA
        and not section.Characteristics & elf2efi.IMAGE_SCN_MEM_DISCARDABLE
    )
    if initialized_data_size != pe.OPTIONAL_HEADER.SizeOfInitializedData:
        print(
            f'SizeOfInitializedData is {pe.OPTIONAL_HEADER.SizeOfInitializedData:#x}, expected '
            f'{initialized_data_size:#x} from summing non-discardable initialized-data sections',
            file=sys.stderr,
        )
        sys.exit(1)


def check_sections(pe, elf_file):
    pe_names = set()
    string_table = get_string_table(pe)

    for section in pe.sections:
        name = resolve_section_name(section.Name, string_table)
        pe_names.add(name)
        file_addr = section.PointerToRawData
        virtual_address = section.VirtualAddress
        print(f'{name:20s} file=0x{file_addr:08x} virt=0x{virtual_address:08x}')

        if not re.fullmatch(r'\.[\w.]*', name):
            print(f'Resolved section name {name!r} looks malformed', file=sys.stderr)
            sys.exit(1)

        if file_addr % elf2efi.FILE_ALIGNMENT != 0:
            print(
                f'File address of {name} section is not aligned to {elf2efi.FILE_ALIGNMENT} bytes',
                file=sys.stderr,
            )
            sys.exit(1)

        if virtual_address % elf2efi.SECTION_ALIGNMENT != 0:
            print(
                f'Virtual address of {name} section is not aligned to {elf2efi.SECTION_ALIGNMENT} bytes',
                file=sys.stderr,
            )
            sys.exit(1)

        if name in elf2efi.DWARF_SECTION_NAMES:
            if not section.Characteristics & elf2efi.IMAGE_SCN_MEM_DISCARDABLE:
                print(f'DWARF section {name} is not marked discardable', file=sys.stderr)
                sys.exit(1)

            elf_section = elf_file.get_section_by_name(name)
            data = pe.__data__[file_addr : file_addr + section.Misc_VirtualSize]
            if elf_section is None or data != elf_section.data():
                print(f'Section {name} data differs in ELF and PE', file=sys.stderr)
                sys.exit(1)

    return pe_names


def main():
    pe_path = sys.argv[1]
    elf_path = sys.argv[2]
    expected_extra_sections = int(sys.argv[3])
    expect_debug_info = bool(int(sys.argv[4]))

    pe = pefile.PE(pe_path, fast_load=True)
    check_header_reserve(pe, expected_extra_sections)
    check_initialized_data_size(pe)
    with open(elf_path, 'rb') as f:
        elf_file = elffile.ELFFile(f)
        pe_names = check_sections(pe, elf_file)
        check_build_id(pe, elf_path, elf_file)
        if expect_debug_info:
            if not any(name in elf2efi.DWARF_SECTION_NAMES for name in pe_names):
                print(f'{pe_path} has no DWARF sections, but should', file=sys.stderr)
                sys.exit(1)
            check_debug_sections(elf_file, pe_names)


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(f'Usage: {sys.argv[0]} pe-image elf-image extra-sections expect-debug-info')
        sys.exit(1)

    main()
