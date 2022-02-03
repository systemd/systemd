#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import glob
import os
import pathlib
import subprocess
import sys
try:
    import colorama as c
    GREEN = c.Fore.GREEN
    YELLOW = c.Fore.YELLOW
    RED = c.Fore.RED
    RESET_ALL = c.Style.RESET_ALL
    BRIGHT = c.Style.BRIGHT
except ImportError:
    GREEN = YELLOW = RED = RESET_ALL = BRIGHT = ''

class total:
    total = None
    good = 0
    skip = 0
    fail = 0

def argument_parser():
    p = argparse.ArgumentParser()
    p.add_argument('-u', '--unsafe', action='store_true',
                   help='run "unsafe" tests too')
    p.add_argument('-A', '--artifact_directory',
                   help='store output from failed tests in this dir')
    return p

opts = argument_parser().parse_args()

tests = glob.glob('/usr/lib/systemd/tests/test-*')
if opts.unsafe:
    tests += glob.glob('/usr/lib/systemd/tests/unsafe/test-*')

if not opts.artifact_directory and os.getenv('ARTIFACT_DIRECTORY'):
    opts.artifact_directory = os.getenv('ARTIFACT_DIRECTORY')

total.total = len(tests)
for test in tests:
    name = os.path.basename(test)

    ex = subprocess.run(test, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if ex.returncode == 0:
        print(f'{GREEN}PASS: {name}{RESET_ALL}')
        total.good += 1
    elif ex.returncode == 77:
        print(f'{YELLOW}SKIP: {name}{RESET_ALL}')
        total.skip += 1
    else:
        print(f'{RED}FAIL: {name}{RESET_ALL}')
        total.fail += 1

        output_file = None
        if opts.artifact_directory:
            output_dir = pathlib.Path(opts.artifact_directory) / 'unit-tests'
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / name
            output_file.write_bytes(ex.stdout)

        try:
            print(ex.stdout.decode('utf-8'))
        except UnicodeDecodeError:
            print(f'{BRIGHT}Note, some test output shown here is not UTF-8')
            if output_file:
                print(f'For actual test output see artifact file {output_file}')
            print(f'{RESET_ALL}')
            print(ex.stdout.decode('utf-8', errors='replace'))
    sys.stdout.flush()


print(f'{BRIGHT}OK: {total.good} SKIP: {total.skip} FAIL: {total.fail}{RESET_ALL}')
sys.exit(total.fail > 0)
