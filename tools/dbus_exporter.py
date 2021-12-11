#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run, PIPE


def extract_interfaces_xml(output_dir, executable):
    list_interfaces_process = run(
        args=[executable.absolute(), '--bus-introspect', 'list'],
        stdout=PIPE,
        check=True,
        universal_newlines=True,
    )

    interfaces_lines = list_interfaces_process.stdout.splitlines()

    interface_names = [x.split()[1] for x in interfaces_lines]

    for interface_name in interface_names:
        interface_introspection_run = run(
            args=[executable.absolute(), '--bus-introspect', interface_name],
            stdout=PIPE,
            check=True,
            universal_newlines=True,
        )

        interface_file_name = output_dir / (interface_name + '.xml')
        with open(interface_file_name, mode='w') as f:
            f.write(interface_introspection_run.stdout)
        interface_file_name.chmod(0o644)


def iterate_executables(output_dir, executables):
    output_dir.mkdir(mode=0o755, exist_ok=True)

    for exe in executables:
        extract_interfaces_xml(output_dir, exe)


def main():
    parser = ArgumentParser()

    parser.add_argument(
        'output',
        type=Path,
    )

    parser.add_argument(
        'executables',
        type=Path,
        nargs='+',
    )

    args = parser.parse_args()

    iterate_executables(args.output, args.executables)


if __name__ == '__main__':
    main()
