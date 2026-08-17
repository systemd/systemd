#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: set tw=110 sw=4 ts=4 et:

import ctypes
import os
import re
import struct
import subprocess
import sys

try:
    import elf2efi
    import pefile
    from elftools.elf import elffile
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_SIZEOF_SYMBOL = 18


def resolve_section_name(pe, section):
    raw = section.Name.rstrip(b'\x00')
    if not raw.startswith(b'/'):
        return raw.decode()

    if pe.FILE_HEADER.PointerToSymbolTable == 0:
        raise ValueError(f'Indirect section name {raw!r} but PE has no symbol/string table')

    string_table = pe.FILE_HEADER.PointerToSymbolTable + IMAGE_SIZEOF_SYMBOL * pe.FILE_HEADER.NumberOfSymbols
    if string_table + 4 > len(pe.__data__):
        raise ValueError(f'String table offset {string_table:#x} is beyond the end of the file')

    table_size = struct.unpack_from('<I', pe.__data__, string_table)[0]

    try:
        offset = int(raw[1:])
    except ValueError as e:
        raise ValueError(f'Indirect section name {raw!r} is not a valid string table offset') from e

    if not 4 <= offset < table_size:
        raise ValueError(f'COFF string table offset {offset} out of bounds (table size {table_size})')

    start = string_table + offset
    end = pe.__data__.find(b'\x00', start, string_table + table_size)
    if end == -1:
        raise ValueError(f'COFF string table entry at offset {offset} is not NUL-terminated')

    return pe.__data__[start:end].decode()


def get_elf_build_id(elf_path):
    try:
        readelf = subprocess.run(
            ['readelf', '-n', elf_path],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, 'LC_ALL': 'C'},
        )
    except FileNotFoundError:
        print('readelf not found, skipping', file=sys.stderr)
        sys.exit(77)
    except subprocess.CalledProcessError as e:
        print(f'readelf failed: {e.stderr.strip()}', file=sys.stderr)
        sys.exit(1)

    m = re.search(r'Build ID: ([0-9a-f]+)', readelf.stdout)
    return bytes.fromhex(m.group(1)) if m else None


def get_elf_dwarf_section_names(elf_path):
    try:
        readelf = subprocess.run(
            ['readelf', '--wide', '-S', elf_path],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, 'LC_ALL': 'C'},
        )
    except FileNotFoundError:
        print('readelf not found, skipping', file=sys.stderr)
        sys.exit(77)
    except subprocess.CalledProcessError as e:
        print(f'readelf failed: {e.stderr.strip()}', file=sys.stderr)
        sys.exit(1)

    names = set(re.findall(r'\]\s+(\.\S+)', readelf.stdout))
    return names & set(elf2efi.DWARF_SECTION_NAMES)


def check_debug_sections(elf_path, pe_names):
    elf_dwarf_names = get_elf_dwarf_section_names(elf_path)
    if not elf_dwarf_names <= pe_names:
        print(
            f'DWARF sections in ELF but missing (or misresolved) in PE: '
            f'{sorted(elf_dwarf_names - pe_names)}',
            file=sys.stderr,
        )
        sys.exit(1)


def check_build_id(pe, elf_path):
    build_id = get_elf_build_id(elf_path)
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

    signature = pe.__data__[raw_data_file_offset : raw_data_file_offset + 4]
    if signature != b'RSDS':
        print(f'Expected RSDS CodeView signature, found {signature!r}', file=sys.stderr)
        sys.exit(1)

    guid = pe.__data__[raw_data_file_offset + 4 : raw_data_file_offset + 20]
    print(f'CodeView GUID: {guid.hex()}')


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


def check_sections(pe, elf_path):
    pe_names = set()
    with open(elf_path, 'rb') as f:
        elf_file = elffile.ELFFile(f)

        for section in pe.sections:
            name = resolve_section_name(pe, section)
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
    pe_names = check_sections(pe, elf_path)
    check_build_id(pe, elf_path)

    if expect_debug_info:
        if not any(name in elf2efi.DWARF_SECTION_NAMES for name in pe_names):
            print(f'{pe_path} has no DWARF sections, but should', file=sys.stderr)
            sys.exit(1)
        check_debug_sections(elf_path, pe_names)


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(f'Usage: {sys.argv[0]} pe-image elf-image extra-sections expect-debug-info')
        sys.exit(1)

    main()
