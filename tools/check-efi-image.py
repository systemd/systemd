#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: set tw=110 sw=4 ts=4 et:

import re
import struct
import subprocess
import sys

try:
    import pefile
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_SIZEOF_SYMBOL = 18
DEBUG_DIRECTORY_ENTRY_FORMAT = '<12xI4xII'
DEBUG_DIRECTORY_ENTRY_SIZE = struct.calcsize(DEBUG_DIRECTORY_ENTRY_FORMAT)


def resolve_section_name(pe, section):
    raw = section.Name.rstrip(b'\x00')
    if not raw.startswith(b'/'):
        return raw.decode()

    string_table = pe.FILE_HEADER.PointerToSymbolTable + IMAGE_SIZEOF_SYMBOL * pe.FILE_HEADER.NumberOfSymbols
    start = string_table + int(raw[1:])
    end = pe.__data__.find(b'\x00', start)
    return pe.__data__[start:end].decode()


def get_elf_build_id(elf_path):
    try:
        readelf = subprocess.run(['readelf', '-n', elf_path], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print('readelf not found', file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f'readelf failed: {e.stderr.strip()}', file=sys.stderr)
        sys.exit(1)

    m = re.search(r'Build ID: ([0-9a-f]+)', readelf.stdout)
    return bytes.fromhex(m.group(1)) if m else None


def get_pe_codeview_signature(pe_path):
    try:
        objdump = subprocess.run(['objdump', '-p', pe_path], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print('objdump not found', file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f'objdump failed: {e.stderr.strip()}', file=sys.stderr)
        sys.exit(1)

    m = re.search(r'RSDS signature ([0-9a-f]+)', objdump.stdout)
    return bytes.fromhex(m.group(1)) if m else None


def check_debug_information(pe, pe_path, elf_path):
    build_id = get_elf_build_id(elf_path)
    debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]

    if debug_dir.VirtualAddress == 0:
        if build_id is not None:
            print('ELF has a build-id but PE has no debug directory', file=sys.stderr)
            sys.exit(1)
        return

    n_entries = debug_dir.Size // DEBUG_DIRECTORY_ENTRY_SIZE
    base_offset = pe.get_offset_from_rva(debug_dir.VirtualAddress)
    entries = [
        struct.unpack_from(
            DEBUG_DIRECTORY_ENTRY_FORMAT, pe.__data__, base_offset + i * DEBUG_DIRECTORY_ENTRY_SIZE
        )
        for i in range(n_entries)
    ]
    codeview_entries = [
        (raw_data_rva, raw_data_file_offset)
        for entry_type, raw_data_rva, raw_data_file_offset in entries
        if entry_type == IMAGE_DEBUG_TYPE_CODEVIEW
    ]
    if len(codeview_entries) != 1:
        print(
            f'Expected exactly one CODEVIEW debug directory entry, found {len(codeview_entries)} '
            f'among {n_entries} entries',
            file=sys.stderr,
        )
        sys.exit(1)

    raw_data_rva, raw_data_file_offset = codeview_entries[0]

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

    if build_id is not None:
        objdump_signature = get_pe_codeview_signature(pe_path)
        if objdump_signature != build_id:
            print(
                f'objdump-reported CodeView signature {objdump_signature.hex() if objdump_signature else None} '
                f'does not match ELF build-id {build_id.hex()}',
                file=sys.stderr,
            )
            sys.exit(1)


def main():
    pe_path = sys.argv[1]
    elf_path = sys.argv[2]

    pe = pefile.PE(pe_path, fast_load=True)

    for section in pe.sections:
        name = resolve_section_name(pe, section)
        file_addr = section.PointerToRawData
        virt_addr = section.VirtualAddress
        print(f'{name:20s} file=0x{file_addr:08x} virt=0x{virt_addr:08x}')

        if not re.fullmatch(r'\.[\w.]*', name):
            print(f'Resolved section name {name!r} looks malformed', file=sys.stderr)
            return 1

        if file_addr % 512 != 0:
            print(f'File address of {name} section is not aligned to 512 bytes', file=sys.stderr)
            return 1

        if virt_addr % 512 != 0:
            print(f'Virt address of {name} section is not aligned to 512 bytes', file=sys.stderr)
            return 1

    check_debug_information(pe, pe_path, elf_path)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} pe-image elf-image')
        sys.exit(1)

    sys.exit(main())
