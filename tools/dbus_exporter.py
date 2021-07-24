#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run, PIPE


def extract_interfaces_xml(output_dir, executable) -> None:
    list_interfaces_process = run(
        args=[
            executable.absolute(),
            '--bus-introspect', 'list',
        ],
        stdout=PIPE,
    )
    list_interfaces_process.check_returncode()

    interfaces_lines = list_interfaces_process.stdout.decode().splitlines()

    interface_names = [x.split('\t')[1] for x in interfaces_lines]

    for interface_name in interface_names:
        interface_introspection_run = run(
            args=[
                executable.absolute(),
                '--bus-introspect', interface_name,
            ],
            stdout=PIPE,
        )

        interface_introspection_run.check_returncode()

        with open(output_dir / (interface_name + '.xml'), mode='wb') as f:
            f.write(interface_introspection_run.stdout)


def iterate_executables(output_dir, executables) -> None:
    output_dir.mkdir(mode=0o755, exist_ok=True)

    for exe in executables:
        extract_interfaces_xml(output_dir, exe)


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument(
        '--output',
        type=Path,
        required=True,
    )

    parser.add_argument(
        '--executables',
        type=Path,
        required=True,
        nargs='+',
    )

    args = parser.parse_args()

    iterate_executables(args.output, args.executables)


if __name__ == '__main__':
    main()
