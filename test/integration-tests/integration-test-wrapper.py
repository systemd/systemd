#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Test wrapper command for driving integration tests."""

import argparse
import base64
import dataclasses
import datetime
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import FrameType
from typing import Optional

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


@dataclasses.dataclass(frozen=True)
class Summary:
    distribution: str
    release: str
    architecture: str
    builddir: Path
    buildsubdir: Path
    environment: dict[str, str]

    @classmethod
    def get(cls, args: argparse.Namespace) -> 'Summary':
        j = json.loads(
            subprocess.run(
                [
                    args.mkosi,
                    '--directory', os.fspath(args.mkosi_dir),
                    '--json',
                    'summary',
                ],
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
        )  # fmt: skip

        return Summary(
            distribution=j['Images'][-1]['Distribution'],
            release=j['Images'][-1]['Release'],
            architecture=j['Images'][-1]['Architecture'],
            builddir=Path(j['Images'][-1]['BuildDirectory']),
            buildsubdir=Path(j['Images'][-1]['BuildSubdirectory']),
            environment=j['Images'][-1]['Environment'],
        )


def process_coredumps(args: argparse.Namespace, journal_file: Path) -> bool:
    # Collect executable paths of all coredumps and filter out the expected ones.

    if args.coredump_exclude_regex:
        exclude_regex = re.compile(args.coredump_exclude_regex)
    else:
        exclude_regex = None

    result = subprocess.run(
        [
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
            'coredumpctl',
            '--file', journal_file,
            '--no-pager',
            'info',
            *(coredump['exe'] for coredump in coredumps),
        ],
        check=True,
    )  # fmt: skip

    return True


def process_sanitizer_report(args: argparse.Namespace, journal_file: Path) -> bool:
    # Collect sanitizer reports from the journal file.

    if args.sanitizer_exclude_regex:
        exclude_regex = re.compile(args.sanitizer_exclude_regex)
    else:
        exclude_regex = None

    total = 0
    fatal = 0
    asan = 0
    ubsan = 0
    msan = 0

    # Internal errors:
    # ==2554==LeakSanitizer has encountered a fatal error.
    # ==2554==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
    # ==2554==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
    fatal_begin = re.compile(r'==[0-9]+==.+?\w+Sanitizer has encountered a fatal error')
    fatal_end = re.compile(r'==[0-9]+==HINT:\s+\w+Sanitizer')

    # 'Standard' errors:
    standard_begin = re.compile(r'([0-9]+: runtime error|==[0-9]+==.+?\w+Sanitizer)')
    standard_end = re.compile(r'SUMMARY:\s+(\w+)Sanitizer')

    # extract COMM
    find_comm = re.compile(r'^\[[.0-9 ]+?\]\s(.*?:)\s')

    with subprocess.Popen(
        [
            'journalctl',
            '--output', 'short-monotonic',
            '--no-hostname',
            '--quiet',
            '--priority', 'info',
            '--file', journal_file,
        ],
        stdout=subprocess.PIPE,
        text=True,
    ) as p:  # fmt: skip
        assert p.stdout

        is_fatal = False
        is_standard = False
        comm = None

        while True:
            line = p.stdout.readline()
            if not line and p.poll() is not None:
                break

            if not is_standard and fatal_begin.search(line):
                m = find_comm.search(line)
                if m:
                    if exclude_regex and exclude_regex.search(m.group(1)):
                        continue
                    comm = m.group(1)

                sys.stderr.write(line)

                is_fatal = True
                total += 1
                fatal += 1
                continue

            if is_fatal:
                if comm and comm not in line:
                    continue

                sys.stderr.write(line)

                if fatal_end.search(line):
                    print(file=sys.stderr)
                    is_fatal = False
                    comm = None
                continue

            if standard_begin.search(line):
                m = find_comm.search(line)
                if m:
                    if exclude_regex and exclude_regex.search(m.group(1)):
                        continue
                    comm = m.group(1)

                sys.stderr.write(line)

                is_standard = True
                total += 1
                continue

            if is_standard:
                if comm and comm not in line:
                    continue

                sys.stderr.write(line)

                kind = standard_end.search(line)
                if kind:
                    print(file=sys.stderr)
                    is_standard = False
                    comm = None

                    t = kind.group(1)
                    if t == 'Address':
                        asan += 1
                    elif t == 'UndefinedBehavior':
                        ubsan += 1
                    elif t == 'Memory':
                        msan += 1

    if total > 0:
        print(
            f'Found {total} sanitizer issues ({fatal} internal, {asan} asan, {ubsan} ubsan, {msan} msan).',
            file=sys.stderr,
        )
    else:
        print('No sanitizer issues found.', file=sys.stderr)

    return total > 0


def process_coverage(args: argparse.Namespace, summary: Summary, name: str, journal_file: Path) -> None:
    coverage = subprocess.run(
        [
            'journalctl',
            '--file', journal_file,
            '--field=COVERAGE_TAR',
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout  # fmt: skip

    (args.meson_build_dir / 'test/coverage').mkdir(exist_ok=True)

    initial = args.meson_build_dir / 'test/coverage/initial.coverage-info'
    output = args.meson_build_dir / f'test/coverage/{name}.coverage-info'

    for b64 in coverage.splitlines():
        tarball = base64.b64decode(b64)

        with tempfile.TemporaryDirectory(prefix='coverage-') as tmp:
            subprocess.run(
                [
                    'tar',
                    '--extract',
                    '--file', '-',
                    '--directory', tmp,
                    '--keep-directory-symlink',
                    '--no-overwrite-dir',
                    '--zstd',
                ],
                input=tarball,
                check=True,
            )  # fmt: skip

            for p in Path(tmp).iterdir():
                if not p.name.startswith('#'):
                    continue

                dst = Path(tmp) / p.name.replace('#', '/').lstrip('/')
                dst.parent.mkdir(parents=True, exist_ok=True)
                p.rename(dst)

            subprocess.run(
                [
                    'find',
                    tmp,
                    '-name', '*.gcda',
                    '-size', '0',
                    '-delete',
                ],
                input=tarball,
                check=True,
            )  # fmt: skip

            subprocess.run(
                [
                    'rsync',
                    '--archive',
                    '--prune-empty-dirs',
                    '--include=*/',
                    '--include=*.gcno',
                    '--exclude=*',
                    f'{os.fspath(summary.builddir / summary.buildsubdir)}/',
                    os.fspath(Path(tmp) / 'work/build'),
                ],
                check=True,
            )

            subprocess.run(
                [
                    'lcov',
                    *(
                        [
                            '--gcov-tool', 'llvm-cov',
                            '--gcov-tool', 'gcov',
                        ]
                        if summary.environment.get('LLVM', '0') == '1'
                        else []
                    ),
                    '--directory', tmp,
                    '--base-directory', 'src/',
                    '--capture',
                    '--exclude', '*.gperf',
                    '--output-file', f'{output}.new',
                    '--ignore-errors', 'inconsistent,inconsistent,source,negative',
                    '--substitute', 's#src/src#src#g',
                    '--no-external',
                    '--quiet',
                ],
                check=True,
                cwd=os.fspath(args.mkosi_dir),
            )  # fmt: skip

            subprocess.run(
                [
                    'lcov',
                    '--ignore-errors', 'inconsistent,inconsistent,format,corrupt,empty',
                    '--add-tracefile', output if output.exists() else initial,
                    '--add-tracefile', f'{output}.new',
                    '--output-file', output,
                    '--quiet',
                ],
                check=True,
                cwd=os.fspath(args.mkosi_dir),
            )  # fmt: skip

            Path(f'{output}.new').unlink()

            print(f'Wrote coverage report for {name} to {output}', file=sys.stderr)


def statfs(path: Path) -> str:
    return subprocess.run(
        ['stat', '--file-system', os.fspath(path), '--format=%T'],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()


INTERRUPTED = False


def onsignal(signal: int, frame: Optional[FrameType]) -> None:
    global INTERRUPTED
    if INTERRUPTED:
        return

    INTERRUPTED = True
    raise KeyboardInterrupt()


def main() -> None:
    signal.signal(signal.SIGINT, onsignal)
    signal.signal(signal.SIGTERM, onsignal)
    signal.signal(signal.SIGHUP, onsignal)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mkosi', default=None)
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
    parser.add_argument('--sanitizer-exclude-regex', required=True)
    parser.add_argument('--rtc', action=argparse.BooleanOptionalAction)
    parser.add_argument('--tpm', action=argparse.BooleanOptionalAction)
    parser.add_argument('--skip', action=argparse.BooleanOptionalAction)
    parser.add_argument('mkosi_args', nargs='*')
    args = parser.parse_args()

    if not args.mkosi:
        args.mkosi = shutil.which('mkosi')
        if not args.mkosi:
            print('Could not find mkosi which is required to run the integration tests', file=sys.stderr)
            sys.exit(1)

    # The meson source directory can either be the top-level repository directory or the
    # test/integration-tests/standalone subdirectory in the repository directory. The mkosi configuration
    # will always be a parent directory of one of these directories and at most 4 levels upwards, so don't
    # look further than that.
    dirs = [args.meson_source_dir] + list(args.meson_source_dir.parents)
    for p in dirs[: min(len(dirs), 4)]:
        if (p / 'mkosi/mkosi.conf').exists():
            setattr(args, 'mkosi_dir', p)
            break
    else:
        print(
            f'Directory with mkosi config not found in any parent directories of {args.meson_source_dir}',
            file=sys.stderr,
        )
        exit(1)

    if args.slow and not bool(int(os.getenv('SYSTEMD_SLOW_TESTS', '0'))):
        print(
            f'SYSTEMD_SLOW_TESTS=1 not found in environment, skipping {args.name}',
            file=sys.stderr,
        )
        exit(77)

    if args.vm and bool(int(os.getenv('TEST_NO_QEMU', '0'))):
        print(f'TEST_NO_QEMU=1, skipping {args.name}', file=sys.stderr)
        exit(77)

    if args.skip:
        print(f'meson requirements for test {args.name} were not fulfilled, skipping', file=sys.stderr)
        exit(77)

    for s in os.getenv('TEST_SKIP', '').split():
        if s in args.name:
            print(f'Skipping {args.name} due to TEST_SKIP', file=sys.stderr)
            exit(77)

    keep_journal = os.getenv('TEST_SAVE_JOURNAL', 'fail')
    shell = bool(int(os.getenv('TEST_SHELL', '0')))
    summary = Summary.get(args)

    # Keep list in sync with TEST-06-SELINUX.sh
    if args.name == 'TEST-06-SELINUX' and summary.distribution not in ('centos', 'fedora', 'opensuse'):
        print('Skipping TEST-06-SELINUX, only enabled for CentOS/Fedora/openSUSE', file=sys.stderr)
        exit(77)

    if shell and not sys.stdin.isatty():
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
            Environment=TEST_MATCH_SUBTEST={os.environ['TEST_MATCH_SUBTEST']}
            """
        )

    if os.getenv('TEST_MATCH_TESTCASE'):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_MATCH_TESTCASE={os.environ['TEST_MATCH_TESTCASE']}
            """
        )

    if os.getenv('TEST_RUN_DFUZZER'):
        dropin += textwrap.dedent(
            f"""
            [Service]
            Environment=TEST_RUN_DFUZZER={os.environ['TEST_RUN_DFUZZER']}
            """
        )

    if os.getenv('TEST_JOURNAL_USE_TMP', '0') == '1':
        if statfs(Path('/tmp')) != 'tmpfs' and statfs(Path('/dev/shm')) == 'tmpfs':
            tmp = Path('/dev/shm')
        else:
            tmp = Path('/tmp')

        journal_file = tmp / f'systemd-integration-tests/journal/{name}.journal'
    else:
        journal_file = (args.meson_build_dir / f'test/journal/{name}.journal').absolute()

    journal_file.unlink(missing_ok=True)

    if not sys.stdin.isatty():
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
            Wants=multi-user.target getty-pre.target
            Before=getty-pre.target

            [Service]
            StandardInput=tty
            StandardOutput=inherit
            StandardError=inherit
            TTYReset=yes
            TTYVHangup=yes
            IgnoreSIGPIPE=no
            # bash ignores SIGTERM
            KillSignal=SIGHUP
            """
        )

    if sys.stdin.isatty():
        dropin += textwrap.dedent(
            """
            [Service]
            ExecStartPre=/usr/lib/systemd/tests/testdata/integration-test-setup.sh setup
            ExecStopPost=/usr/lib/systemd/tests/testdata/integration-test-setup.sh finalize
            StateDirectory=%N
            """
        )

    if args.rtc:
        if sys.version_info >= (3, 12):
            now = datetime.datetime.now(datetime.UTC)
        else:
            now = datetime.datetime.utcnow()

        rtc = datetime.datetime.strftime(now, r'%Y-%m-%dT%H:%M:%S')
    else:
        rtc = None

    # Whenever possible, boot without an initrd. This requires the target distribution kernel to have the
    # necessary modules (virtio-blk, ext4) builtin.
    if args.firmware == 'linux-noinitrd' and (summary.distribution, summary.release) not in (
        ('fedora', 'rawhide'),
        ('arch', 'rolling'),
    ):
        firmware = 'linux'
    else:
        firmware = args.firmware

    vm = args.vm or os.getuid() != 0 or os.getenv('TEST_PREFER_QEMU', '0') == '1'

    cmd = [
        args.mkosi,
        '--directory', os.fspath(args.mkosi_dir),
        '--machine', name,
        '--ephemeral=yes',
        *(['--forward-journal', journal_file] if journal_file else []),
        *(
            [
                '--credential', f'systemd.extra-unit.emergency-exit.service={shlex.quote(EMERGENCY_EXIT_SERVICE)}',  # noqa: E501
                '--credential', f'systemd.unit-dropin.emergency.target={shlex.quote(EMERGENCY_EXIT_DROPIN)}',
            ]
            if not sys.stdin.isatty()
            else []
        ),
        '--credential', f'systemd.unit-dropin.{args.unit}={shlex.quote(dropin)}',
        '--runtime-network=none',
        *([f'--qemu-args=-rtc base={rtc}'] if rtc else []),
        *args.mkosi_args,
        '--firmware', firmware,
        *(['--kvm', 'no'] if int(os.getenv('TEST_NO_KVM', '0')) else []),
        '--tpm', 'yes' if args.tpm else 'no',
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
                        'loglevel=6',
                    ]
                    if not sys.stdin.isatty()
                    else []
                ),
            ]
        ),
        '--credential', f"journal.storage={'persistent' if sys.stdin.isatty() else args.storage}",
        *(['--runtime-build-sources=no', '--register=no'] if not sys.stdin.isatty() else []),
        'vm' if vm else 'boot',
        *(['--', '--capability=CAP_BPF'] if not vm else []),
    ]  # fmt: skip

    try:
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
    except KeyboardInterrupt:
        result = subprocess.CompletedProcess(args=cmd, returncode=-signal.SIGINT)

    coredumps = process_coredumps(args, journal_file)

    sanitizer = False
    if summary.environment.get('SANITIZERS'):
        sanitizer = process_sanitizer_report(args, journal_file)

    if (
        summary.environment.get('COVERAGE', '0') == '1'
        and result.returncode in (args.exit_code, 77)
        and not coredumps
        and not sanitizer
    ):
        process_coverage(args, summary, name, journal_file)

    if keep_journal == '0' or (
        keep_journal == 'fail'
        and result.returncode in (args.exit_code, 77)
        and not coredumps
        and not sanitizer
    ):
        journal_file.unlink(missing_ok=True)
    elif os.getenv('TEST_JOURNAL_USE_TMP', '0') == '1' and journal_file.exists():
        dst = args.meson_build_dir / f'test/journal/{name}.journal'
        dst.parent.mkdir(parents=True, exist_ok=True)
        journal_file = Path(shutil.move(journal_file, dst))

    if shell or (result.returncode in (args.exit_code, 77) and not coredumps and not sanitizer):
        exit_code = 0 if shell or result.returncode == args.exit_code else 77
        exit_str = 'succeeded' if exit_code == 0 else 'skipped'
    else:
        # 0 also means we failed so translate that to a non-zero exit code to mark the test as failed.
        exit_code = result.returncode or 1
        exit_str = 'failed'

    if journal_file.exists():
        ops = []

        if os.getenv('GITHUB_ACTIONS'):
            id = os.environ['GITHUB_RUN_ID']
            wf = os.environ['GITHUB_WORKFLOW']
            iter = os.environ['GITHUB_RUN_ATTEMPT']
            runner = os.environ['TEST_RUNNER']
            artifact = (
                f'ci-{wf}-{id}-{iter}-{summary.distribution}-{summary.release}-{runner}-failed-test-journals'  # noqa: E501
            )
            ops += [f'gh run download {id} --name {artifact} -D ci/{artifact}']
            journal_file = Path(f'ci/{artifact}/test/journal/{name}.journal')

        ops += [f'journalctl --file {journal_file} --no-hostname -o short-monotonic -u {args.unit} -p info']

        print(
            f'Test {exit_str}, relevant logs can be viewed with: \n\n{(" && ".join(ops))}\n', file=sys.stderr
        )

    exit(exit_code)


if __name__ == '__main__':
    main()
