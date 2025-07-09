#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-2.1-or-later

# Convert the bpf_{cmd,map_type,prog_type,attach_type} enums into a string
# array to be used as configuration options

import re
import sys


def print_usage_and_exit() -> None:
    print(f'Usage: {sys.argv[0]} <code|doc> <header>')
    sys.exit(1)


if len(sys.argv) != 3:
    print_usage_and_exit()

output = sys.argv[1]
header = sys.argv[2]

if output not in ['code', 'doc']:
    print(f'Invalid format: {format}')
    print_usage_and_exit()

with open(header) as file:
    inEnum = False
    enumValues: list[str] = []
    enumName = ''

    if output == 'doc':
        print("""\
<?xml version="1.0"?>
<!DOCTYPE bpf-delegates PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN"
  "http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd">
<para>
""")

    for line in file:
        line = line.strip()

        if inEnum:
            # Inside an enum definition
            if re.match(r'^\s*}', line):
                # End of an enum definition
                inEnum = False
                # Print the enum values as a static const char* array
                if output == 'code':
                    print(f'static const char* const {enumName}_table[] = {{')
                else:
                    print(f'<para id="{enumName}">')
                for enumValue in enumValues:
                    words = enumValue.split('_')
                    enumValue = words[0] + ''.join(word.capitalize() for word in words[1:])
                    if output == 'code':
                        print(f'\t"{enumValue}",')
                    else:
                        print(f'<constant>{enumValue}</constant>')
                if output == 'code':
                    print('};')
                else:
                    print('</para>')
                enumValues = []
            else:
                # Collect enum values
                match = re.fullmatch(r'(\w+)\b,', line)
                if match and len(match.groups()) > 0 and not match[1].startswith('__'):
                    enumValues.append(match[1])
        elif match := re.match(r'^\s*enum\s+bpf_(cmd|map_type|prog_type|attach_type)+\s*{', line):
            # Start of a new enum
            inEnum = True
            enumName = 'bpf_delegate_' + match[1]

    if output == 'doc':
        print('</para>')
