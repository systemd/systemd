#!/usr/bin/env python3
import sys, re

print('#include <stdio.h>')
for header in sys.argv[2:]:
    print('#include "{}"'.format(header.split('/')[-1]))

print('''
void* functions[] = {''')

for line in open(sys.argv[1]):
    match = re.search('^ +([a-zA-Z0-9_]+);', line)
    if match:
        print('    {},'.format(match.group(1)))

print('''};

int main(void) {
    unsigned i;
    for (i = 0; i < sizeof(functions)/sizeof(void*); i++)
         printf("%p\\n", functions[i]);
    return 0;
}''')
