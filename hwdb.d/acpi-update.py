#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from csv import reader
from enum import Enum

def read_table(a):

    table = []

    with open(a, newline='') as csvfile:
        for row in reader(csvfile):
            if row[0] == "Company":
                # Skip header
                continue
            table.append(row)

    table.sort(key=lambda x: x[1])

    for row in table:
        # Some IDs end with whitespace, while they didn't in the old HTML table, so it's probably
        # a mistake, strip it.
        print("\nacpi:{0}*:\n ID_VENDOR_FROM_DATABASE={1}".format(row[1].strip(), row[0].strip()))

print('# This file is part of systemd.\n'
      '#\n'
      '# Data imported from:\n'
      '#     https://uefi.org/uefi-pnp-export\n'
      '#     https://uefi.org/uefi-acpi-export')

read_table('acpi_id_registry.csv')
read_table('pnp_id_registry.csv')
