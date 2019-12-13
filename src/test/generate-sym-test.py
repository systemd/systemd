#!/usr/bin/env python3
import sys, re

print('#include <stdio.h>')
for header in sys.argv[2:]:
    print('#include "{}"'.format(header.split('/')[-1]))

print('''
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
    unsigned i;
    for (i = 0; i < sizeof(symbols)/sizeof(void*); i++)
         printf("%p\\n", symbols[i]);
    return 0;
}''')
