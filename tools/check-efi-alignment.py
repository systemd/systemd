#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: set tw=110 sw=4 ts=4 et:

import sys

import pefile


def main():
    pe = pefile.PE(sys.argv[1], fast_load=True)

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode()
        file_addr = section.PointerToRawData
        virt_addr = section.VirtualAddress
        print(f"{name:10s} file=0x{file_addr:08x} virt=0x{virt_addr:08x}")

        if file_addr % 512 != 0:
            print(f"File address of {name} section is not aligned to 512 bytes", file=sys.stderr)
            return 1

        if virt_addr % 512 != 0:
            print(f"Virt address of {name} section is not aligned to 512 bytes", file=sys.stderr)
            return 1

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} pe-image")
        sys.exit(1)

    sys.exit(main())
