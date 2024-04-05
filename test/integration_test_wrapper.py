#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.

Note: This is deliberately rough and only intended to drive existing tests
with the expectation that as part of formally defining the API it will be tidy.

'''

import argparse
import logging
from pathlib import Path
import shlex
import subprocess


TEST_EXIT_DROPIN = """\
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


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--test-name', required=True)
parser.add_argument('--mkosi-image-name', required=True)
parser.add_argument('--mkosi-output-path', required=True, type=Path)
parser.add_argument('--test-number', required=True)
parser.add_argument('--setup-selinux', default=False, action='store_true')
parser.add_argument('--skip-shutdown', default=False, action='store_true')
parser.add_argument('--no-emergency-exit',
                    dest='emergency_exit', default=True, action='store_false',
                    help="Disable emergency exit drop-ins for interactive debugging")
parser.add_argument('mkosi_args', nargs="*")

def main():
    logging.basicConfig(level=logging.DEBUG)
    args = parser.parse_args()

    test_unit_name = f"testsuite-{args.test_number}.service"
    # Machine names shouldn't have / since it's used as a file name
    # and it must be a valid hostname so 64 chars max
    machine_name = args.test_name.replace('/', '_')[:64]

    logging.debug(f"test name: {args.test_name}\n"
                  f"test number: {args.test_number}\n"
                  f"image: {args.mkosi_image_name}\n"
                  f"mkosi output path: {args.mkosi_output_path}\n"
                  f"mkosi args: {args.mkosi_args}\n"
                  f"skip shutdown: {args.skip_shutdown}\n"
                  f"emergency exit: {args.emergency_exit}")

    journal_file = Path(f"{machine_name}.journal").absolute()
    logging.info(f"Capturing journal to {journal_file}")

    mkosi_args = [
        'mkosi',
        '--directory', Path('..').resolve(),
        '--output-dir', args.mkosi_output_path.absolute(),
        '--machine', machine_name,
        '--image', args.mkosi_image_name,
        '--format=disk',
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
        *(
            [f"--credential=systemd.unit-dropin.{test_unit_name}={shlex.quote(TEST_EXIT_DROPIN)}"]
            if not args.skip_shutdown
            else []
        ),
        '--append',
        '--kernel-command-line-extra',
        ' '.join([
            'systemd.hostname=H',
            *(
                ['apparmor=0', 'selinux=1', 'enforcing=0', 'lsm=selinux']
                if args.setup_selinux
                else [] # We assume mkosi.conf disables LSMs by default
            ),
            f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-{args.test_number}.units:/usr/lib/systemd/tests/testdata/units:",
            'systemd.unit=testsuite.target',
            f"systemd.wants={test_unit_name}",
        ]),
        *args.mkosi_args,
    ]

    mkosi_args += ['qemu']

    logging.debug(f"Running {' '.join(shlex.quote(str(a)) for a in mkosi_args)}")

    try:
        subprocess.run(mkosi_args, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode not in (0, 77):
            suggested_command = [
                'journalctl',
                '--all',
                '--no-hostname',
                '-o', 'short-monotonic',
                '--file', journal_file,
                f"_SYSTEMD_UNIT={test_unit_name}",
                '+', f"SYSLOG_IDENTIFIER=testsuite-{args.test_number}.sh",
                '+', 'PRIORITY=4',
                '+', 'PRIORITY=3',
                '+', 'PRIORITY=2',
                '+', 'PRIORITY=1',
                '+', 'PRIORITY=0',
            ]
            logging.info("Test failed, relevant logs can be viewed with: "
                         f"{' '.join(shlex.quote(str(s)) for s in suggested_command)}")
        exit(e.returncode)


if __name__ == '__main__':
    main()
