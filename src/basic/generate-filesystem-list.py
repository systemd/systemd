#!/usr/bin/env python3
import sys
import os

keywords_section = False

for line in open(sys.argv[1]):
    if keywords_section:
        print('"{}\\0"'.format(line.split(',')[0].strip()))
    elif line.startswith('%%'):
        keywords_section = True
