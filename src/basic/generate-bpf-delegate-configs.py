#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-2.1-or-later

# Convert the bpf_{cmd,map_type,prog_type,attach_type} enums into a string
# array to be used as configuration options

import re
import sys

def print_usage_and_exit():
    print(f'Usage: {sys.argv[0]} header <header>')
    print(f'Usage: {sys.argv[0]} doc <header> <filterEnum>')
    sys.exit(1)

if len(sys.argv) < 3 or len(sys.argv) > 4:
    print_usage_and_exit()

output=sys.argv[1]
header=sys.argv[2]
filterEnum=sys.argv[3] if len(sys.argv) > 3 else None

if output not in ['header', 'doc']:
    print(f'Invalid format: {format}')
    print_usage_and_exit()

if output == 'doc' and not filterEnum or output == 'header' and filterEnum:
    print_usage_and_exit()

with open(header) as file:
    inEnum = False
    enumValues = []

    for line in file:
        line = line.strip()

        if inEnum:
            # Inside an enum definition
            if re.match(r'^\s*}', line):
                # End of an enum definition
                inEnum = False
                # Print the enum values as a static const char* array
                if output == 'header':
                    print(f'static const char* const {enumName}_table[] = {{')
                else:
                    print('<node>')
                for enumValue in enumValues:
                    words = enumValue.split('_')
                    enumValue = words[0] + ''.join(word.capitalize() for word in words[1:])
                    if output == 'header':
                        print(f'\t"{enumValue}",')
                    else:
                        print(f'<literal>{enumValue}</literal>')
                if output == 'header':
                    print('};')
                else:
                    print('</node>')
                enumValues = []
            else:
                # Collect enum values
                match = re.fullmatch(r'(\w+)\b,', line)
                if match and len(match.groups()) > 0 and not match[1].startswith('__'):
                    enumValues.append(match[1])
        elif match := re.match(r'^\s*enum\s+bpf_(cmd|map_type|prog_type|attach_type)+\s*{', line):
            # Start of a new enum
            if filterEnum and filterEnum != 'bpf_' + match[1]:
                continue
            inEnum = True
            enumName = 'bpf_delegate_' + match[1]
