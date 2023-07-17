#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=consider-using-with

import os
import pathlib
import re
import sys

PROJECT_ROOT = pathlib.Path(os.getenv('PROJECT_SOURCE_ROOT', '.'))

def check_file(filename):
    seen = set()
    good = True
    for n, line in enumerate(open(filename)):
        m = re.match(r'^\s*#\s*include\s*[<"](\S*)[>"]', line)
        if m:
            include = m.group(1)
            if include in seen:
                try:
                    filename = pathlib.Path(filename).resolve().relative_to(PROJECT_ROOT)
                except ValueError:
                    pass
                print(f'{filename}:{n}: {line.strip()}')
                good = False
            seen.add(include)
    return good

if __name__ == '__main__':
    all_good = all(check_file(name) for name in sys.argv[1:])
    sys.exit(0 if all_good else 1)
