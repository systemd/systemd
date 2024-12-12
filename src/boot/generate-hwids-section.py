#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import sys
from pathlib import Path

# We import ukify.py, which is a template file. But only __version__ is
# substituted, which we don't care about here. Having the .py suffix makes it
# easier to import the file.
sys.path.append(os.path.dirname(__file__) + '/../ukify')
import ukify

BYTES_PER_LINE = 16

hwids = ukify.parse_hwid_dir(Path(sys.argv[1]))

print(
    """/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stddef.h>
#include <stdint.h>

const uint8_t hwids_section_data[] = {
    """,
    end='',
)

for i, b in enumerate(hwids):
    print(f'0x{b:02X}, ', end='')
    if i % BYTES_PER_LINE == BYTES_PER_LINE - 1:
        print('\n    ', end='')
    elif i == len(hwids) - 1:
        print('')

print(
    """};
const size_t hwids_section_len =""",
    f'{len(hwids)};',
)
