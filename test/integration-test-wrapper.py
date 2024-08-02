#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.
'''

import argparse
import json
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
    parser.add_argument('mkosi_args', nargs="*")
    args = parser.parse_args()

    if not bool(int(os.getenv("SYSTEMD_INTEGRATION_TESTS", "0"))):
        print(f"SYSTEMD_INTEGRATION_TESTS=1 not found in environment, skipping {args.name}", file=sys.stderr)
        exit(77)

    if args.slow and not bool(int(os.getenv("SYSTEMD_SLOW_TESTS", "0"))):
        print(f"SYSTEMD_SLOW_TESTS=1 not found in environment, skipping {args.name}", file=sys.stderr)
        exit(77)

    if args.vm and bool(int(os.getenv("TEST_NO_QEMU", "0"))):
        print(f"TEST_NO_QEMU=1, skipping {args.name}", file=sys.stderr)
        exit(77)

    keep_journal = os.getenv("TEST_SAVE_JOURNAL", "fail")
    shell = bool(int(os.getenv("TEST_SHELL", "0")))

    if shell and not sys.stderr.isatty():
        print(f"--interactive must be passed to meson test to use TEST_SHELL=1", file=sys.stderr)
        exit(1)

    name = args.name + (f"-{i}" if (i := os.getenv("MESON_TEST_ITERATION")) else "")

    dropin = textwrap.dedent(
        """\
        [Service]
        StandardOutput=journal+console
        """
    )

    if not shell:
        dropin += textwrap.dedent(
            f"""
            [Unit]
            SuccessAction=exit
            SuccessActionExitStatus=123
            """
        )

    if os.getenv("TEST_MATCH_SUBTEST"):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_MATCH_SUBTEST={os.environ["TEST_MATCH_SUBTEST"]}
            """
        )

    if os.getenv("TEST_MATCH_TESTCASE"):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_MATCH_TESTCASE={os.environ["TEST_MATCH_TESTCASE"]}
            """
        )

    journal_file = None
    if not sys.stderr.isatty():
        dropin += textwrap.dedent(
            """
            [Unit]
            FailureAction=exit
            """
        )

        journal_file = (args.meson_build_dir / (f"test/journal/{name}.journal")).absolute()
        journal_file.unlink(missing_ok=True)
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
                '--credential',
                f"systemd.extra-unit.emergency-exit.service={shlex.quote(EMERGENCY_EXIT_SERVICE)}",
                '--credential',
                f"systemd.unit-dropin.emergency.target={shlex.quote(EMERGENCY_EXIT_DROPIN)}",
            ]
            if not sys.stderr.isatty()
            else []
        ),
        '--credential',
        f"systemd.unit-dropin.{args.unit}={shlex.quote(dropin)}",
        '--runtime-network=none',
        '--runtime-scratch=no',
        *args.mkosi_args,
        '--qemu-firmware', args.firmware,
        '--qemu-kvm', "auto" if not bool(int(os.getenv("TEST_NO_KVM", "0"))) else "no",
        '--kernel-command-line-extra',
        ' '.join([
            'systemd.hostname=H',
            f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/{args.name}.units:/usr/lib/systemd/tests/testdata/units:",
            *([f"systemd.unit={args.unit}"] if not shell else []),
            'systemd.mask=systemd-networkd-wait-online.service',
            *(
                [
                    "systemd.mask=serial-getty@.service",
                    "systemd.show_status=no",
                    "systemd.crash_shell=0",
                    "systemd.crash_action=poweroff",
                ]
                if not sys.stderr.isatty()
                else []
            ),
        ]),
        '--credential', f"journal.storage={'persistent' if sys.stderr.isatty() else args.storage}",
        *(['--runtime-build-sources=no'] if not sys.stderr.isatty() else []),
        'qemu' if args.vm or os.getuid() != 0 else 'boot',
    ]

    result = subprocess.run(cmd)

    if journal_file and (keep_journal == "0" or (result.returncode in (args.exit_code, 77) and keep_journal == "fail")):
        journal_file.unlink(missing_ok=True)

    if shell or result.returncode in (args.exit_code, 77):
        exit(0 if shell or result.returncode == args.exit_code else 77)

    if journal_file:
        ops = []

        if os.getenv("GITHUB_ACTIONS"):
            id = os.environ["GITHUB_RUN_ID"]
            iteration = os.environ["GITHUB_RUN_ATTEMPT"]
            j = json.loads(
                subprocess.run(
                    [
                        args.mkosi,
                        "--directory", os.fspath(args.meson_source_dir),
                        "--json",
                        "summary",
                    ],
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout
            )
            distribution = j["Images"][-1]["Distribution"]
            release = j["Images"][-1]["Release"]
            artifact = f"ci-mkosi-{id}-{iteration}-{distribution}-{release}-failed-test-journals"
            ops += [f"gh run download {id} --name {artifact} -D ci/{artifact}"]
            journal_file = Path(f"ci/{artifact}/test/journal/{name}.journal")

        ops += [f"journalctl --file {journal_file} --no-hostname -o short-monotonic -u {args.unit} -p info"]

        print("Test failed, relevant logs can be viewed with: \n\n"
              f"{(' && '.join(ops))}\n", file=sys.stderr)

    # 0 also means we failed so translate that to a non-zero exit code to mark the test as failed.
    exit(result.returncode or 1)


if __name__ == '__main__':
    main()
