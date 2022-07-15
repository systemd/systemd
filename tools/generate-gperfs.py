#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Generate %-from-name.gperf from %-list.txt
"""

import sys

name, prefix, input = sys.argv[1:]

print("""\
%{
#if __GNUC__ >= 7
_Pragma("GCC diagnostic ignored \\"-Wimplicit-fallthrough\\"")
#endif
%}""")
print("""\
struct {}_name {{ const char* name; int id; }};
%null-strings
%%""".format(name))

for line in open(input):
    print("{0}, {1}{0}".format(line.rstrip(), prefix))
