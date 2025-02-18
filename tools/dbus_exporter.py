#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import os
from argparse import ArgumentParser
from pathlib import Path
from subprocess import PIPE, run


def extract_interfaces_xml(output_dir, executable):
    # If proc is not mounted, set LD_ORIGIN_PATH so that shared/core libs can be found,
    # as glibc looks at /proc/self/exe when resolving RPATH
    env = os.environ.copy()
    if not os.path.exists('/proc/self'):
        env["LD_ORIGIN_PATH"] = executable.parent.as_posix()

    proc = run(
        args=[executable.absolute(), '--bus-introspect', 'list'],
        stdout=PIPE,
        env=env,
        check=True,
        universal_newlines=True)

    interface_names = (x.split()[1] for x in proc.stdout.splitlines())

    for interface_name in interface_names:
        proc = run(
            args=[executable.absolute(), '--bus-introspect', interface_name],
            stdout=PIPE,
            env=env,
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
    # Make sure we don't inherit any setgid/setuid bit or such.
    args.output.chmod(mode=0o755)
    for exe in args.executables:
        extract_interfaces_xml(args.output, exe)

if __name__ == '__main__':
    main()
