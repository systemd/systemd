#!/usr/bin/python

import ast
import re

def read_os_release():
    try:
        f = open('/etc/os-release')
    except FileNotFoundError:
        f = open('/usr/lib/os-release')

    for line_number, line in enumerate(f):
        if m := re.match(r'([A-Z][A-Z_0-9]+)=(.*?)\s*$', line):
            name, val = m.groups()
            if val and val[0] in '"\'':
                val = ast.literal_eval(val)
            yield name, val
        else:
            print(f'Warning: bad line {line_number}: {line}', file=sys.stderr)

os_release = dict(read_os_release())

pretty_name = os_release.get('PRETTY_NAME', 'Linux')
print(f'Running on {pretty_name}')

if (os_release.get('ID', 'linux') == 'debian' or
    os_release.get('ID_LIKE', None) == 'debian'):
    print('Looks like Debian!')
