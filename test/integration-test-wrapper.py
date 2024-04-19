#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.

Note: This is deliberately rough and only intended to drive existing tests
with the expectation that as part of formally defining the API it will be tidy.

'''

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys


TEST_DROPIN = """\
[Unit]
SuccessAction=exit
FailureAction=exit
"""


EMERGENCY_EXIT_DROPIN = """\
[Unit]
Wants=emergency-exit.service
"""


EMERGENCY_EXIT_SERVICE = """\
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Conflicts=rescue.service
Before=shutdown.target
Before=rescue.service
FailureAction=exit

[Service]
ExecStart=false
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-name', required=True)
    parser.add_argument('--mkosi-image-name', required=True)
    parser.add_argument('--mkosi-output-path', required=True, type=Path)
    parser.add_argument('--test-number', required=True)
    parser.add_argument('--no-emergency-exit',
                        dest='emergency_exit', default=True, action='store_false',
                        help="Disable emergency exit drop-ins for interactive debugging")
    parser.add_argument('mkosi_args', nargs="*")
    args = parser.parse_args()

    test_unit_name = f"testsuite-{args.test_number}.service"
    # Machine names shouldn't have / since it's used as a file name
    # and it must be a valid hostname so 64 chars max
    machine_name = args.test_name.replace('/', '_')[:64]

    journal_file = Path(f"{machine_name}.journal").absolute()
    journal_file.unlink(missing_ok=True)

    mkosi_args = [
        'mkosi',
        '--directory', Path('..').resolve(),
        '--output-dir', args.mkosi_output_path.absolute(),
        '--machine', machine_name,
        '--image', args.mkosi_image_name,
        '--ephemeral',
        '--forward-journal', journal_file,
        *(
            [
                '--credential',
                f"systemd.extra-unit.emergency-exit.service={shlex.quote(EMERGENCY_EXIT_SERVICE)} "
                f"systemd.unit-dropin.emergency.target={shlex.quote(EMERGENCY_EXIT_DROPIN)}",
            ]
            if args.emergency_exit
            else []
        ),
        f"--credential=systemd.unit-dropin.{test_unit_name}={shlex.quote(TEST_DROPIN)}",
        '--append',
        '--kernel-command-line-extra',
        ' '.join([
            'systemd.hostname=H',
            f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-{args.test_number}.units:/usr/lib/systemd/tests/testdata/units:",
            'systemd.unit=testsuite.target',
            f"systemd.wants={test_unit_name}",
            # Disable status because it duplicates the same info from log messages forwarded to the console.
            'systemd.show_status=false',
            'systemd.journald.max_level_console=info',
        ]),
        *args.mkosi_args,
        'qemu',
    ]

    try:
        subprocess.run(mkosi_args, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode not in (0, 77):
            suggested_command = [
                'journalctl',
                '--no-hostname',
                '-o', 'short-monotonic',
                '--file', journal_file,
                '-u', test_unit_name,
                '-p', 'info',
            ]
            print("Test failed, relevant logs can be viewed with: \n\n"
                  f"{shlex.join(os.fspath(a) for a in suggested_command)}\n", file=sys.stderr)
        exit(e.returncode)


if __name__ == '__main__':
    main()
