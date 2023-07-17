#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=unbalanced-tuple-unpacking,consider-using-f-string

"""
Generate %-from-name.gperf from %-list.txt
"""

import sys

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} name prefix file')
        sys.exit(1)

    name, prefix, file = sys.argv[1:]

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

    with open(file, encoding='utf-8') as f:
        for line in f:
            print("{0}, {1}{0}".format(line.rstrip(), prefix))
