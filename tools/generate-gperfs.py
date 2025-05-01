#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=unbalanced-tuple-unpacking,consider-using-f-string,consider-using-with

"""
Generate %-from-name.gperf from %-list.txt
"""

import sys

if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.exit(f'Usage: {sys.argv[0]} name prefix file [includes...]')

    name, prefix, file, *includes = sys.argv[1:]
    includes = [f"#include {i}" for i in includes]

    # Older versions of python don't allow backslashes
    # in f-strings so use chr(10) for newlines and chr(92)
    # for backslashes instead as a workaround.
    print(f"""\
%{{
_Pragma("GCC diagnostic ignored {chr(92)}"-Wimplicit-fallthrough{chr(92)}"")
#if __GNUC__ >= 15
_Pragma("GCC diagnostic ignored {chr(92)}"-Wzero-as-null-pointer-constant{chr(92)}"")
#endif
{chr(10).join(includes)}
%}}""")
    print(f"""\
struct {name}_name {{ const char* name; int id; }};
%null-strings
%%""")

    for line in open(file):
        print("{0}, {1}{0}".format(line.rstrip(), prefix))
