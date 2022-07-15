#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys

keywords_section = False

for line in open(sys.argv[1]):
    if line[0] == '#':
        continue

    if keywords_section:
        print('"{}\\0"'.format(line.split(',')[0].strip()))
    elif line.startswith('%%'):
        keywords_section = True
