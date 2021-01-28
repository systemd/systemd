#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import os

s390 = 's390' in os.uname().machine
arm = 'arm' in os.uname().machine

for line in open(sys.argv[1]):
    if line.startswith('s390_') and not s390:
        continue
    if line.startswith('arm_') and not arm:
        continue

    print('"{}\\0"'.format(line.strip()))
