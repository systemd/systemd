#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.

Note: This is deliberately rough and only intended to drive existing tests
with the expectation that as part of formally defining the API it will be tidy.

'''

from argparse import ArgumentParser
from contextlib import contextmanager, ExitStack
from logging import getLogger as logging_get_logger, basicConfig as logging_basic_config, DEBUG as LOG_DEBUG
from pathlib import Path
from shlex import quote
from subprocess import DEVNULL, run
from tempfile import TemporaryDirectory


log = logging_get_logger(__name__)


TEST_EXIT_DROPIN = """\
[Unit]
SuccessAction=exit
FailureAction=exit
"""


BUILTIN_KERNEL_COMMAND_LINE_ARGS = (
    'systemd.hostname=H',
    'rw',
    'systemd.default_device_timeout_sec=20',
    'systemd.early_core_pattern=/core',
    'systemd.firstboot=no',
    'noresume',
    'oops=panic',
    'panic=1',
)

parser = ArgumentParser(description=__doc__)
parser.add_argument('--test-name', required=True)
parser.add_argument('--mkosi-image-name', required=True)
parser.add_argument('--mkosi-output-path', required=True, type=Path)
parser.add_argument('--test-number', required=True)
parser.add_argument('--setup-selinux', default=False, action='store_true')
parser.add_argument('--skip-shutdown', default=False, action='store_true')
parser.add_argument('mkosi_args', nargs="*")

def main():
    logging_basic_config(level=LOG_DEBUG)
    args = parser.parse_args()

    test_unit_name = f"testsuite-{args.test_number}.service"
    # Machine names shouldn't have / since it's used as a file name
    # and it must be a valid hostname so 64 chars max
    machine_name = args.test_name.replace('/', '_')[:64]

    log.debug(f"test name: {args.test_name}\n"
              f"test number: {args.test_number}\n"
              f"image: {args.mkosi_image_name}\n"
              f"mkosi output path: {args.mkosi_output_path}\n"
              f"mkosi args: {args.mkosi_args}\n"
              f"skip shutdown: {args.skip_shutdown}")

    with ExitStack() as stack:

        journal_file = Path(f"{machine_name}.journal").absolute()
        log.debug(f"Capturing journal to {journal_file}")

        mkosi_args = [
            'mkosi',
            '--directory', Path('..').resolve(),
            '--output-dir', args.mkosi_output_path.absolute(),
            '--machine', machine_name,
            '--image', args.mkosi_image_name,
            '--format=disk',
            '--ephemeral',
            '--forward-journal', journal_file,
            '--kernel-command-line-extra',
            ' '.join([
                *BUILTIN_KERNEL_COMMAND_LINE_ARGS,
                *(
                    ['apparmor=0', 'selinux=1', 'enforcing=0', 'lsm=selinux']
                    if args.setup_selinux
                    else ['apparmor=0', 'selinux=0', 'enforcing=0']
                ),
                f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-{args.test_number}.units:/usr/lib/systemd/tests/testdata/units:",
                'systemd.unit=testsuite.target',
                f"systemd.wants={test_unit_name}",
            ]),
            *(
                [f"--credential=systemd.unit-dropin.{test_unit_name}={quote(TEST_EXIT_DROPIN)}"]
                if not args.skip_shutdown
                else []
            ),
            *args.mkosi_args,
        ]

        mkosi_args += ['qemu']

        if log.isEnabledFor(LOG_DEBUG):
            log.debug(f"Running {' '.join(quote(str(a)) for a in mkosi_args)}")

        try:
            run(mkosi_args, check=True)
        except SystemExit as e:
            if e.code not in (0, 77):
                log.debug("Attempting journalctl to discover test failure")
                run(['journalctl',
                     '--boot',
                     '--unit', test_unit_name,
                     '--file', journal_file.name,
                    ], stdin=DEVNULL)


if __name__ == '__main__':
    main()
