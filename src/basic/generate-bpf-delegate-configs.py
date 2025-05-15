#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-2.1-or-later

# Convert the bpf_{cmd,map_type,prog_type,attach_type} enums into a string
# array to be used as configuration options

import re
import sys

with open(sys.argv[1], 'r') as file:
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
                print(f'static const char* const {enumName}_table[] = {{')
                for enumValue in enumValues:
                    words = enumValue.split('_')
                    enumValue = words[0] + ''.join(word.capitalize() for word in words[1:])
                    print(f'\t"{enumValue}",')
                print('};')
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
