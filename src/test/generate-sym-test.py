#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys, re

print('#include <stdio.h>')
for header in sys.argv[2:]:
    print('#include "{}"'.format(header.split('/')[-1]))

print('''
/* We want to check deprecated symbols too, without complaining */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

const void* symbols[] = {''')

for line in open(sys.argv[1]):
    match = re.search('^ +([a-zA-Z0-9_]+);', line)
    if match:
        s = match.group(1)
        if s == 'sd_bus_object_vtable_format':
            print('    &{},'.format(s))
        else:
            print('    {},'.format(s))

print('''};

int main(void) {
    for (size_t i = 0; i < sizeof(symbols)/sizeof(void*); i++)
         printf("%p\\n", symbols[i]);
    return 0;
}''')
