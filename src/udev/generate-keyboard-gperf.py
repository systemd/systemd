#!/usr/bin/env python3

"""Generate keyboard-keys-from-name.gperf from keyboard-keys-list.txt
"""

import sys

input = sys.argv[1]

print("""\
struct key_name { const char* name; unsigned short id; };
%null-strings
%%""")

for line in open(input):
    print("{0}, {1}".format(line.rstrip()[4:].lower(), line.rstrip()))
