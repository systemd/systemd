#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
A small tool to dump build size artifact information in JSON.

{
  "$architecture": {
    "$binary": {
      "bss": int,
      "data": int,
      "text": int,
      "total_size": int,
    }
  }
}
"""


import argparse
import json
import pathlib
import platform
import subprocess
import sys
from typing import TypedDict

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("Error: 'elftools' python module not found.", file=sys.stderr)
    sys.exit(1)


class BinaryStats(TypedDict):
    bss: int
    data: int
    text: int
    total_size: int


def collect_binary_size(binary: pathlib.Path) -> BinaryStats:
    with open(binary, 'rb') as f:
        elf = ELFFile(f)
        sections = {section.name: section['sh_size'] for section in elf.iter_sections()}
        return BinaryStats(bss=sections.get('.bss', 0),
                           data=sections.get('.data', 0),
                           text=sections.get('.text', 0),
                           total_size=binary.stat().st_size)


def collect_sizes(build_dir: pathlib.Path):
    result = {}
    targets = json.loads(subprocess.check_output(['meson', 'introspect', '--targets', build_dir]))

    for target in targets:
        if not target.get('installed'):
            continue

        if target['type'] not in ('executable', 'shared library'):
            continue

        if not (filenames := target.get('filename', [])):
            continue
        if not (path := pathlib.Path(filenames[0])).exists():
            continue
        if not (install_filenames := target.get('install_filename', [])):
            continue

        install_path = install_filenames[0]
        result[install_path] = collect_binary_size(path)

    return dict(sorted(result.items()))


def main():
    parser = argparse.ArgumentParser(description='Dump installed binary sizes as JSON.')
    parser.add_argument('build_dir', type=pathlib.Path, help='Path to the meson build directory.')
    parser.add_argument('-o', '--output', type=pathlib.Path, help='Output file (default: stdout).')
    args = parser.parse_args()

    sizes = {platform.machine(): collect_sizes(args.build_dir)}
    if args.output:
        args.output.write_text(json.dumps(sizes, indent=2) + '\n')
    else:
        json.dump(sizes, sys.stdout, indent=2)


if __name__ == '__main__':
    main()
