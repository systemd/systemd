#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from csv import reader

# pylint: disable=consider-using-with

def read_table(filename):
    table = list(reader(open(filename, newline='')))
    table = table[1:]  # Skip header
    table.sort(key=lambda x: x[1])

    for row in table:
        # Some IDs end with whitespace, while they didn't in the old HTML table, so it's probably
        # a mistake, strip it.
        print(f'\nacpi:{row[1].strip()}*:\n ID_VENDOR_FROM_DATABASE={row[0].strip()}')

print('''\
# This file is part of systemd.
#
# Data imported from:
#     https://uefi.org/uefi-pnp-export
#     https://uefi.org/uefi-acpi-export''')

read_table('acpi_id_registry.csv')
read_table('pnp_id_registry.csv')
