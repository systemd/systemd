#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-2.1-or-later

# Embed the contents of unit files passed on the command line into a C array
# initializer, so that the manager can fall back to a built-in copy when no
# unit file is found on disk. Comment and empty lines are stripped to keep the
# embedded strings small. The unit name is derived from each file's basename.

import os
import pathlib
import sys

def strip_comments(text: str) -> str:
    # Unit files use '#' and ';' as comment markers at the start of a line.
    lines = (line for line in text.splitlines()
             if line and not line[0] in '#;')
    return '\n'.join(lines) + '\n'

def c_escape(text: str) -> str:
    return text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

for path in sys.argv[1:]:
    path = pathlib.Path(path)
    data = strip_comments(path.read_text())
    print(f'{{ "{path.name}", "{c_escape(data)}" }},')
