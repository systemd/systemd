#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
A helper to compare 'systemd-analyze dump' outputs.

systemd-analyze dump >/var/tmp/dump1
(reboot)
tools/analyze-dump-sort.py /var/tmp/dump1 → this does a diff from dump1 to current

systemd-analyze dump >/var/tmp/dump2
tools/analyze-dump-sort.py /var/tmp/{dump1,dump2} → this does a diff from dump1 to dump2
"""

import argparse
import tempfile
import subprocess

def sort_dump(sourcefile, destfile=None):
    if destfile is None:
        destfile = tempfile.NamedTemporaryFile('wt')

    units = {}
    unit = []

    same = []

    for line in sourcefile:
        line = line.rstrip()

        header = line.split(':')[0]
        if 'Timestamp' in header or 'Invocation ID' in header or 'PID' in header:
            line = header + ': …'

        if line.startswith('->'):
            if unit:
                units[unit[0]] = unit
            unit = [line]
        elif line.startswith('\t'):
            assert unit

            if same and same[0].startswith(header):
                same.append(line)
            else:
                unit.extend(sorted(same, key=str.lower))
                same = [line]
        else:
            print(line, file=destfile)

    if unit:
        units[unit[0]] = unit

    for unit in sorted(units.values()):
        print('\n'.join(unit), file=destfile)

    destfile.flush()
    return destfile

def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('one')
    p.add_argument('two', nargs='?')
    p.add_argument('--user', action='store_true')
    return p.parse_args()

if __name__ == '__main__':
    opts = parse_args()

    one = sort_dump(open(opts.one))
    if opts.two:
        two = sort_dump(open(opts.two))
    else:
        user = ['--user'] if opts.user else []
        two = subprocess.run(['systemd-analyze', 'dump', *user],
                             capture_output=True, text=True, check=True)
        two = sort_dump(two.stdout.splitlines())
    with subprocess.Popen(['diff', '-U10', one.name, two.name], stdout=subprocess.PIPE) as diff:
        subprocess.Popen(['less'], stdin=diff.stdout)
