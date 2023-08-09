#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# This file is distributed under the MIT license, see below.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Prints out journal entries with no or bad catalog explanations.
"""

import re

from systemd import id128, journal


# pylint: disable=consider-using-f-string
def log_entry(entry):
    if 'CODE_FILE' in entry:
        # some of our code was using 'CODE_FUNCTION' instead of 'CODE_FUNC'
        print('{}:{} {}'.format(entry.get('CODE_FILE', '???'),
                                entry.get('CODE_LINE', '???'),
                                entry.get('CODE_FUNC', None) or entry.get('CODE_FUNCTION', '???')))
    print('    {}'.format(entry.get('MESSAGE', 'no message!')))
    for k, v in entry.items():
        if k.startswith('CODE_') or k in {'MESSAGE_ID', 'MESSAGE'}:
            continue
        print(f'    {k}={v}')
    print()

if __name__ == '__main__':
    j = journal.Reader()
    logged = set()
    pattern = re.compile('@[A-Z0-9_]+@')

    mids = { v:k for k,v in id128.__dict__.items() if k.startswith('SD_MESSAGE') }

    for i, x in enumerate(j):
        if i % 1000 == 0:
            print(i, end='\r')

        try:
            mid = x['MESSAGE_ID']
        except KeyError:
            continue
        name = mids.get(mid, 'unknown')

        try:
            desc = journal.get_catalog(mid)
        except FileNotFoundError:
            if mid in logged:
                continue

            print(f'{name} {mid.hex}: no catalog entry')
            log_entry(x)
            logged.add(mid)
            continue

        fields = [field[1:-1] for field in pattern.findall(desc)]
        for field in fields:
            index = (mid, field)
            if field in x or index in logged:
                continue
            print(f'{name} {mid.hex}: no field {field}')
            log_entry(x)
            logged.add(index)
