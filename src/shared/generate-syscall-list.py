#!/usr/bin/env python3
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
