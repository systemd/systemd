#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""This script prints each line of a file as a C string literal and escapes backslashes, double quotes,
and newlines. The compiler concatenates adjacent string literals. A C file that #includes the output as
the initializer of a char array gets the contents of the file as one string."""

import sys

for line in open(sys.argv[1]):
    line = line.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    print(f'"{line}"')
