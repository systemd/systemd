#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.

Note: This is deliberately rough and only intended to drive existing tests
with the expectation that as part of formally defining the API it will be tidy.

'''

import argparse
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path


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
    parser.add_argument('--meson-source-dir', required=True, type=Path)
    parser.add_argument('--meson-build-dir', required=True, type=Path)
    parser.add_argument('--test-name', required=True)
    parser.add_argument('--test-number', required=True)
    parser.add_argument('mkosi_args', nargs="*")
    args = parser.parse_args()

    test_unit = f"testsuite-{args.test_number}.service"

    dropin = textwrap.dedent(
        """\
        [Unit]
        After=multi-user.target network.target
        Requires=multi-user.target

        [Service]
        StandardOutput=journal+console
        """
    )

    if not sys.stderr.isatty():
        dropin += textwrap.dedent(
            """
            [Unit]
            SuccessAction=exit
            FailureAction=exit
            """
        )

        journal_file = (args.meson_build_dir / (f"test/journal/{args.test_name}.journal")).absolute()
        journal_file.unlink(missing_ok=True)
    else:
        journal_file = None

    cmd = [
        'mkosi',
        '--directory', os.fspath(args.meson_source_dir),
        '--output-dir', os.fspath(args.meson_build_dir / 'mkosi.output'),
        '--extra-search-path', os.fspath(args.meson_build_dir),
        '--machine', args.test_name,
        '--ephemeral',
        *(['--forward-journal', journal_file] if journal_file else []),
        *(
            [
                '--credential',
                f"systemd.extra-unit.emergency-exit.service={shlex.quote(EMERGENCY_EXIT_SERVICE)}",
                '--credential',
                f"systemd.unit-dropin.emergency.target={shlex.quote(EMERGENCY_EXIT_DROPIN)}",
                '--kernel-command-line-extra=systemd.mask=serial-getty@.service',
            ]
            if not sys.stderr.isatty()
            else []
        ),
        '--credential',
        f"systemd.unit-dropin.{test_unit}={shlex.quote(dropin)}",
        '--append',
        '--kernel-command-line-extra',
        ' '.join([
            'systemd.hostname=H',
            f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-{args.test_number}.units:/usr/lib/systemd/tests/testdata/units:",
            f"systemd.unit={test_unit}",
        ]),
        *args.mkosi_args,
        'qemu',
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode != 77 and journal_file:
            cmd = [
                'journalctl',
                '--no-hostname',
                '-o', 'short-monotonic',
                '--file', journal_file,
                '-u', test_unit,
                '-p', 'info',
            ]
            print("Test failed, relevant logs can be viewed with: \n\n"
                  f"{shlex.join(str(a) for a in cmd)}\n", file=sys.stderr)
        exit(e.returncode)

    # Do not keep journal files for tests that don't fail.
    if journal_file:
        journal_file.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
