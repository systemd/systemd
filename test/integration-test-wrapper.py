#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Test wrapper command for driving integration tests."""

import argparse
import json
import os
import re
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


def process_coredumps(args: argparse.Namespace, journal_file: Path) -> bool:
    # Collect executable paths of all coredumps and filter out the expected ones.

    if args.coredump_exclude_regex:
        exclude_regex = re.compile(args.coredump_exclude_regex)
    else:
        exclude_regex = None

    result = subprocess.run(
        [
            args.mkosi,
            '--directory', os.fspath(args.meson_source_dir),
            '--extra-search-path', os.fspath(args.meson_build_dir),
            'sandbox',
            'coredumpctl',
            '--file', journal_file,
            '--json=short',
        ],
        stdout=subprocess.PIPE,
        text=True,
    )  # fmt: skip

    # coredumpctl returns a non-zero exit status if there are no coredumps.
    if result.returncode != 0:
        return False

    coredumps = json.loads(result.stdout)

    coredumps = [
        coredump for coredump in coredumps if not exclude_regex or not exclude_regex.search(coredump['exe'])
    ]

    if not coredumps:
        return False

    subprocess.run(
        [
            args.mkosi,
            '--directory', os.fspath(args.meson_source_dir),
            '--extra-search-path', os.fspath(args.meson_build_dir),
            'sandbox',
            'coredumpctl',
            '--file', journal_file,
            '--no-pager',
            'info',
            *(coredump['exe'] for coredump in coredumps),
        ],
        check=True,
    )  # fmt: skip

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mkosi', required=True)
    parser.add_argument('--meson-source-dir', required=True, type=Path)
    parser.add_argument('--meson-build-dir', required=True, type=Path)
    parser.add_argument('--name', required=True)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--storage', required=True)
    parser.add_argument('--firmware', required=True)
    parser.add_argument('--slow', action=argparse.BooleanOptionalAction)
    parser.add_argument('--vm', action=argparse.BooleanOptionalAction)
    parser.add_argument('--exit-code', required=True, type=int)
    parser.add_argument('--coredump-exclude-regex', required=True)
    parser.add_argument('mkosi_args', nargs='*')
    args = parser.parse_args()

    if not bool(int(os.getenv('SYSTEMD_INTEGRATION_TESTS', '0'))):
        print(
            f'SYSTEMD_INTEGRATION_TESTS=1 not found in environment, skipping {args.name}',
            file=sys.stderr,
        )
        exit(77)

    if args.slow and not bool(int(os.getenv('SYSTEMD_SLOW_TESTS', '0'))):
        print(
            f'SYSTEMD_SLOW_TESTS=1 not found in environment, skipping {args.name}',
            file=sys.stderr,
        )
        exit(77)

    if args.vm and bool(int(os.getenv('TEST_NO_QEMU', '0'))):
        print(f'TEST_NO_QEMU=1, skipping {args.name}', file=sys.stderr)
        exit(77)

    for s in os.getenv('TEST_SKIP', '').split():
        if s in args.name:
            print(f'Skipping {args.name} due to TEST_SKIP', file=sys.stderr)
            exit(77)

    keep_journal = os.getenv('TEST_SAVE_JOURNAL', 'fail')
    shell = bool(int(os.getenv('TEST_SHELL', '0')))

    if shell and not sys.stderr.isatty():
        print(
            '--interactive must be passed to meson test to use TEST_SHELL=1',
            file=sys.stderr,
        )
        exit(1)

    name = args.name + (f'-{i}' if (i := os.getenv('MESON_TEST_ITERATION')) else '')

    dropin = textwrap.dedent(
        """\
        [Service]
        StandardOutput=journal+console
        """
    )

    if not shell:
        dropin += textwrap.dedent(
            """
            [Unit]
            SuccessAction=exit
            SuccessActionExitStatus=123
            """
        )

    if os.getenv('TEST_MATCH_SUBTEST'):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_MATCH_SUBTEST={os.environ["TEST_MATCH_SUBTEST"]}
            """
        )

    if os.getenv('TEST_MATCH_TESTCASE'):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_MATCH_TESTCASE={os.environ["TEST_MATCH_TESTCASE"]}
            """
        )

    journal_file = (args.meson_build_dir / (f'test/journal/{name}.journal')).absolute()
    journal_file.unlink(missing_ok=True)

    if not sys.stderr.isatty():
        dropin += textwrap.dedent(
            """
            [Unit]
            FailureAction=exit
            """
        )
    elif not shell:
        dropin += textwrap.dedent(
            """
            [Unit]
            Wants=multi-user.target
            """
        )

    cmd = [
        args.mkosi,
        '--directory', os.fspath(args.meson_source_dir),
        '--output-dir', os.fspath(args.meson_build_dir / 'mkosi.output'),
        '--extra-search-path', os.fspath(args.meson_build_dir),
        '--machine', name,
        '--ephemeral',
        *(['--forward-journal', journal_file] if journal_file else []),
        *(
            [
                '--credential', f'systemd.extra-unit.emergency-exit.service={shlex.quote(EMERGENCY_EXIT_SERVICE)}',  # noqa: E501
                '--credential', f'systemd.unit-dropin.emergency.target={shlex.quote(EMERGENCY_EXIT_DROPIN)}',
            ]
            if not sys.stderr.isatty()
            else []
        ),
        '--credential', f'systemd.unit-dropin.{args.unit}={shlex.quote(dropin)}',
        '--runtime-network=none',
        '--runtime-scratch=no',
        *args.mkosi_args,
        '--qemu-firmware',
        args.firmware,
        *(['--qemu-kvm', 'no'] if int(os.getenv('TEST_NO_KVM', '0')) else []),
        '--kernel-command-line-extra',
        ' '.join(
            [
                'systemd.hostname=H',
                f'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/{args.name}.units:/usr/lib/systemd/tests/testdata/units:',
                *([f'systemd.unit={args.unit}'] if not shell else []),
                'systemd.mask=systemd-networkd-wait-online.service',
                *(
                    [
                        'systemd.mask=serial-getty@.service',
                        'systemd.show_status=error',
                        'systemd.crash_shell=0',
                        'systemd.crash_action=poweroff',
                    ]
                    if not sys.stderr.isatty()
                    else []
                ),
            ]
        ),
        '--credential', f"journal.storage={'persistent' if sys.stderr.isatty() else args.storage}",
        *(['--runtime-build-sources=no'] if not sys.stderr.isatty() else []),
        'qemu' if args.vm or os.getuid() != 0 else 'boot',
    ]  # fmt: skip

    result = subprocess.run(cmd)

    # On Debian/Ubuntu we get a lot of random QEMU crashes. Retry once, and then skip if it fails again.
    if args.vm and result.returncode == 247 and args.exit_code != 247:
        if journal_file:
            journal_file.unlink(missing_ok=True)
        result = subprocess.run(cmd)
        if args.vm and result.returncode == 247 and args.exit_code != 247:
            print(
                f'Test {args.name} failed due to QEMU crash (error 247), ignoring',
                file=sys.stderr,
            )
            exit(77)

    coredumps = process_coredumps(args, journal_file)

    if keep_journal == '0' or (
        keep_journal == 'fail' and result.returncode in (args.exit_code, 77) and not coredumps
    ):
        journal_file.unlink(missing_ok=True)

    if shell or (result.returncode in (args.exit_code, 77) and not coredumps):
        exit(0 if shell or result.returncode == args.exit_code else 77)

    ops = []

    if os.getenv('GITHUB_ACTIONS'):
        id = os.environ['GITHUB_RUN_ID']
        iteration = os.environ['GITHUB_RUN_ATTEMPT']
        j = json.loads(
            subprocess.run(
                [
                    args.mkosi,
                    '--directory', os.fspath(args.meson_source_dir),
                    '--json',
                    'summary',
                ],
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
        )  # fmt: skip
        distribution = j['Images'][-1]['Distribution']
        release = j['Images'][-1]['Release']
        artifact = f'ci-mkosi-{id}-{iteration}-{distribution}-{release}-failed-test-journals'
        ops += [f'gh run download {id} --name {artifact} -D ci/{artifact}']
        journal_file = Path(f'ci/{artifact}/test/journal/{name}.journal')

    ops += [f'journalctl --file {journal_file} --no-hostname -o short-monotonic -u {args.unit} -p info']

    print("Test failed, relevant logs can be viewed with: \n\n" f"{(' && '.join(ops))}\n", file=sys.stderr)

    # 0 also means we failed so translate that to a non-zero exit code to mark the test as failed.
    exit(result.returncode or 1)


if __name__ == '__main__':
    main()
