#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys, re

print('''/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* We want to check deprecated symbols too, without complaining */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <stdio.h>
#include <stdlib.h>
''')

for header in sys.argv[3:]:
    print('#include "{}"'.format(header.split('/')[-1]))

print()
print('#include "{}"'.format(sys.argv[2]))
print('''
const struct {
        const char *name;
        const void *symbol;
} symbols_from_sym[] = {''')

for line in open(sys.argv[1]):
    match = re.search('^ +([a-zA-Z0-9_]+);', line)
    if match:
        s = match.group(1)
        if s == 'sd_bus_object_vtable_format':
            print(f'        {{"{s}", &{s}}},')
        else:
            print(f'        {{"{s}", {s}}},')

print('''        {}
};

int main(void) {
        size_t i, j;

        puts("From symbol file:");
        for (i = 0; symbols_from_sym[i].name; i++)
                printf("%p: %s\\n", symbols_from_sym[i].symbol, symbols_from_sym[i].name);
        printf("Found %zu symbols from symbol file.\\n", i);

        puts("\\nFrom source files:");
        for (j = 0; symbols_from_source[j].name; j++)
                printf("%p: %s\\n", symbols_from_source[j].symbol, symbols_from_source[j].name);
        printf("Found %zu symbols from source files.\\n", j);

        return i == j ? EXIT_SUCCESS : EXIT_FAILURE;
}''')
