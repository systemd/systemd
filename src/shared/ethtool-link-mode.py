#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import sys

OVERRIDES = {
    'autoneg' : 'autonegotiation',
}
count = 0

f = open(sys.argv[1])
for line in f:
    if line.startswith('enum ethtool_link_mode_bit_indices {'):
        break
for line in f:
    if line.startswith('}'):
        break
    # ETHTOOL_LINK_MODE_10baseT_Half_BIT	= 0,
    m = re.match(r'^\s*(ETHTOOL_LINK_MODE_(.*)_BIT)\s*=\s*(\d+),', line)
    if not m:
        continue
    enum, name, value = m.groups()

    name = name.lower().replace('_', '-')
    name = OVERRIDES.get(name, name)

    enum = f'[{enum}]'

    print(f'        {enum:50} = "{name}",')
    count += 1

assert count >= 99
