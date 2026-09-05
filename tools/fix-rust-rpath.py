#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Set the runpath of installed programs written in Rust to exactly the given directory.

meson adds rustc's own library directory to the runpath of every Rust program that links a shared
library (a rustup toolchain needs that to find a dynamically linked libstd) and keeps it when installing.
Our programs link libstd statically and must only ever search the directory libsystemd-shared lives in.

Usage: fix-rust-rpath.py RPATH FILE...

FILE is the installed path, $DESTDIR is prepended.
"""

import os
import struct
import sys

DT_NULL = 0
DT_RPATH = 15
DT_RUNPATH = 29
SHT_DYNAMIC = 6


def read_cstring(f, offset: int) -> bytes:
    f.seek(offset)
    s = b''
    while True:
        c = f.read(1)
        if c in (b'', b'\0'):
            return s
        s += c


def fix_rpath(path: str, rpath: bytes) -> None:
    with open(path, 'r+b') as f:
        ident = f.read(16)
        if ident[:4] != b'\x7fELF':
            sys.exit(f'{path}: not an ELF file')

        is64 = ident[4] == 2
        end = '<' if ident[5] == 1 else '>'

        f.seek(0)
        if is64:
            ehdr = struct.unpack(end + '16sHHIQQQIHHHHHH', f.read(64))
        else:
            ehdr = struct.unpack(end + '16sHHIIIIIHHHHHH', f.read(52))
        shoff, shentsize, shnum = ehdr[6], ehdr[11], ehdr[12]

        sections = []
        for i in range(shnum):
            f.seek(shoff + i * shentsize)
            if is64:
                sections.append(struct.unpack(end + 'IIQQQQIIQQ', f.read(64)))
            else:
                sections.append(struct.unpack(end + 'IIIIIIIIII', f.read(40)))

        dynamic = next((s for s in sections if s[1] == SHT_DYNAMIC), None)
        if dynamic is None:
            return

        dynstr = sections[dynamic[6]]
        entsize = 16 if is64 else 8
        entfmt = end + ('qQ' if is64 else 'iI')

        for off in range(dynamic[4], dynamic[4] + dynamic[5], entsize):
            f.seek(off)
            tag, val = struct.unpack(entfmt, f.read(entsize))
            if tag == DT_NULL:
                break
            if tag not in (DT_RPATH, DT_RUNPATH):
                continue

            str_off = dynstr[4] + val
            old = read_cstring(f, str_off)
            if old == rpath:
                continue
            if len(rpath) > len(old):
                sys.exit(f'{path}: runpath {rpath!r} does not fit into {old!r}')

            # Overwrite in place, the string table cannot grow.
            f.seek(str_off)
            f.write(rpath + b'\0' * (len(old) - len(rpath) + 1))
            print(f'Setting runpath of {path} to {rpath.decode()}')


def main() -> None:
    rpath = sys.argv[1].encode()
    destdir = os.environ.get('DESTDIR', '')

    for path in sys.argv[2:]:
        fix_rpath(destdir + path, rpath)


if __name__ == '__main__':
    main()
