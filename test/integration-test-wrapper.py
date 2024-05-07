#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

'''Test wrapper command for driving integration tests.

Note: This is deliberately rough and only intended to drive existing tests
with the expectation that as part of formally defining the API it will be tidy.

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
    parser.add_argument('--meson-source-dir', required=True, type=Path)
    parser.add_argument('--meson-build-dir', required=True, type=Path)
    parser.add_argument('--test-name', required=True)
    parser.add_argument('--test-number', required=True)
    parser.add_argument('--storage', required=True)
    parser.add_argument('--firmware', required=True)
    parser.add_argument('--slow', action=argparse.BooleanOptionalAction)
    parser.add_argument('mkosi_args', nargs="*")
    args = parser.parse_args()

    if not bool(int(os.getenv("SYSTEMD_INTEGRATION_TESTS", "0"))):
        print(f"SYSTEMD_INTEGRATION_TESTS=1 not found in environment, skipping {args.test_name}", file=sys.stderr)
        exit(77)

    if args.slow and not bool(int(os.getenv("SYSTEMD_SLOW_TESTS", "0"))):
        print(f"SYSTEMD_SLOW_TESTS=1 not found in environment, skipping {args.test_name}", file=sys.stderr)
        exit(77)

    name = args.test_name + (f"-{i}" if (i := os.getenv("MESON_TEST_ITERATION")) else "")
    test_unit = f"testsuite-{args.test_number}.service"

    dropin = textwrap.dedent(
        """\
        [Unit]
        After=multi-user.target network.target
        Requires=multi-user.target
        SuccessAction=exit
        SuccessActionExitStatus=123

        [Service]
        StandardOutput=journal+console
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

    if not sys.stderr.isatty():
        dropin += textwrap.dedent(
            """
            [Unit]
            FailureAction=exit
            """
        )

        journal_file = (args.meson_build_dir / (f"test/journal/{name}.journal")).absolute()
        journal_file.unlink(missing_ok=True)
    else:
        journal_file = None

    cmd = [
        'mkosi',
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
        f"systemd.unit-dropin.{test_unit}={shlex.quote(dropin)}",
        '--runtime-network=none',
        '--runtime-scratch=no',
        '--append',
        '--qemu-firmware', args.firmware,
        '--kernel-command-line-extra',
        ' '.join([
            'systemd.hostname=H',
            f"SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-{args.test_number}.units:/usr/lib/systemd/tests/testdata/units:",
            f"systemd.unit={test_unit}",
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
        *args.mkosi_args,
        'qemu',
    ]

    result = subprocess.run(cmd)

    # Return code 123 is the expected success code
    if result.returncode in (123, 77):
        # Do not keep journal files for tests that don't fail.
        if journal_file:
            journal_file.unlink(missing_ok=True)

        exit(0 if result.returncode == 123 else 77)

    if journal_file:
        ops = []

        if os.getenv("GITHUB_ACTIONS"):
            id = os.environ["GITHUB_RUN_ID"]
            iteration = os.environ["GITHUB_RUN_ATTEMPT"]
            j = json.loads(
                subprocess.run(
                    [
                        "mkosi",
                        "--directory", os.fspath(args.meson_source_dir),
                        "--json",
                        "summary",
                    ],
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout
            )
            images = {image["Image"]: image for image in j["Images"]}
            distribution = images["system"]["Distribution"]
            release = images["system"]["Release"]
            artifact = f"ci-mkosi-{id}-{iteration}-{distribution}-{release}-failed-test-journals"
            ops += [f"gh run download {id} --name {artifact} -D ci/{artifact}"]
            journal_file = Path(f"ci/{artifact}/test/journal/{name}.journal")

        ops += [f"journalctl --file {journal_file} --no-hostname -o short-monotonic -u {test_unit} -p info"]

        print("Test failed, relevant logs can be viewed with: \n\n"
              f"{(' && '.join(ops))}\n", file=sys.stderr)

    # 0 also means we failed so translate that to a non-zero exit code to mark the test as failed.
    exit(result.returncode or 1)


if __name__ == '__main__':
    main()
