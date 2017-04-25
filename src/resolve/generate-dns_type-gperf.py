#!/usr/bin/env python3

"""Generate %-from-name.gperf from %-list.txt
"""

import sys

name, prefix, input = sys.argv[1:]

print("""\
struct {}_name {{ const char* name; int id; }};
%null-strings
%%""".format(name))

for line in open(input):
    line = line.rstrip()
    s = line.replace('_', '-')
    print("{}, {}{}".format(s, prefix, line))
