#!/usr/bin/env python3

import dataclasses
import glob
import os
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

@dataclasses.dataclass
class Total:
    total:int
    good:int = 0
    skip:int = 0
    fail:int = 0

tests = glob.glob('/usr/lib/systemd/tests/test-*')
total = Total(total=len(tests))
for test in tests:
    name = os.path.basename(test)

    ex = subprocess.run(test, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ex.returncode == 0:
        print(f'{GREEN}PASS: {name}{RESET_ALL}')
        total.good += 1
    elif ex.returncode == 77:
        print(f'{YELLOW}SKIP: {name}{RESET_ALL}')
        total.skip += 1
    else:
        print(f'{RED}FAIL: {name}{RESET_ALL}')
        total.fail += 1

        # stdout/stderr might not be valid unicode, let's just dump it to the terminal.
        # Also let's reset the style afterwards, in case our output sets something.
        sys.stdout.buffer.write(ex.stdout)
        print(f'{RESET_ALL}{BRIGHT}')
        sys.stdout.buffer.write(ex.stderr)
        print(f'{RESET_ALL}')

print(f'{BRIGHT}OK: {total.good} SKIP: {total.skip} FAIL: {total.fail}{RESET_ALL}')
sys.exit(total.fail > 0)
