#!/usr/bin/python
# SPDX-License-Identifier: MIT-0

import ast
import re
import sys

def read_os_release():
    try:
        filename = '/etc/os-release'
        f = open(filename)
    except FileNotFoundError:
        filename = '/usr/lib/os-release'
        f = open(filename)

    for line_number, line in enumerate(f, start=1):
        line = line.rstrip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'([A-Z][A-Z_0-9]+)=(.*)', line)
        if m:
            name, val = m.groups()
            if val and val[0] in '"\'':
                val = ast.literal_eval(val)
            yield name, val
        else:
            print(f'{filename}:{line_number}: bad line {line!r}',
                  file=sys.stderr)

os_release = dict(read_os_release())

pretty_name = os_release.get('PRETTY_NAME', 'Linux')
print(f'Running on {pretty_name!r}')

if 'debian' in [os_release.get('ID', 'linux'),
                *os_release.get('ID_LIKE', '').split()]:
    print('Looks like Debian!')
