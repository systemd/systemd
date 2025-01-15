#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=unbalanced-tuple-unpacking,consider-using-f-string,consider-using-with

"""
Generate %-from-name.gperf from %-list.txt
"""

import sys

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(f'Usage: {sys.argv[0]} name prefix file')

    name, prefix, file = sys.argv[1:]

    print("""\
%{
_Pragma("GCC diagnostic ignored \\"-Wimplicit-fallthrough\\"")
#if __GNUC__ >= 15
_Pragma("GCC diagnostic ignored \\"-Wzero-as-null-pointer-constant\\"")
#endif
%}""")
    print(f"""\
struct {name}_name {{ const char* name; int id; }};
%null-strings
%%""")

    for line in open(file):
        print("{0}, {1}{0}".format(line.rstrip(), prefix))
