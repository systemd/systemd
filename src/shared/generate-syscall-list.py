#!/usr/bin/env python
import sys

for line in open(sys.argv[1]):
    print('"{}\\0"'.format(line.strip()))
