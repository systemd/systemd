#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys

for line in open(sys.argv[1]):
    print('"{}\\0"'.format(line.strip()))
