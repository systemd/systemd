#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import collections, re

d = collections.defaultdict(list)
for line in open(sys.argv[1]):
    m = re.match(r'^([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+),', line)
    if m:
        d[m.group(1)] += [m.group(2)]

sec_rx = sys.argv[2] if len(sys.argv) > 2 else '.'
sec_rx = re.compile(sec_rx)
unit_type = sys.argv[3] if len(sys.argv) > 3 else None

if unit_type:
    print(unit_type)

for section, items in d.items():
    if not sec_rx.match(section):
        continue
    print(f'[{section}]')
    for item in items:
        print(f'{item}=')
    print()
