#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"Generate %-from-name.gperf from %-list.txt"

import sys

name, prefix, input = sys.argv[1:]

print("""\
%{
#if __GNUC__ >= 7
_Pragma("GCC diagnostic ignored \\"-Wimplicit-fallthrough\\"")
#endif
%}""")
print(f"""\
struct {name}_name {{ const char* name; int id; }};
%null-strings
%%""")

for line in open(input):
    line = line.rstrip()
    s = line.replace('_', '-')
    print(f'{s}, {prefix}{line}')
