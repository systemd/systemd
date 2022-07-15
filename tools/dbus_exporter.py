#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run, PIPE

def extract_interfaces_xml(output_dir, executable):
    proc = run(
        args=[executable.absolute(), '--bus-introspect', 'list'],
        stdout=PIPE,
        check=True,
        universal_newlines=True)

    interface_names = (x.split()[1] for x in proc.stdout.splitlines())

    for interface_name in interface_names:
        proc = run(
            args=[executable.absolute(), '--bus-introspect', interface_name],
            stdout=PIPE,
            check=True,
            universal_newlines=True)

        interface_file_name = output_dir / (interface_name + '.xml')
        interface_file_name.write_text(proc.stdout)
        interface_file_name.chmod(0o644)

def main():
    parser = ArgumentParser()
    parser.add_argument('output',
                        type=Path)
    parser.add_argument('executables',
                        nargs='+',
                        type=Path)

    args = parser.parse_args()

    args.output.mkdir(exist_ok=True)
    for exe in args.executables:
        extract_interfaces_xml(args.output, exe)

if __name__ == '__main__':
    main()
