#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re
import sys

def process_sym_file(file):
    for line in file:
        m = re.search(r'^ +([a-zA-Z0-9_]+);', line)
        if m:
            if m[1] == 'sd_bus_object_vtable_format':
                print('        {{"{0}", &{0}}},'.format(m[1]))
            else:
                print('        {{"{0}", {0}}},'.format(m[1]))

def process_source_file(file):
    for line in file:
        # Functions
        m = re.search(r'^_public_\s+(\S+\s+)+\**(\w+)\s*\(', line)
        if m:
            print('        {{ "{0}", {0} }},'.format(m[2]))
        # Variables
        m = re.search(r'^_public_\s+(\S+\s+)+\**(\w+)\s*=', line)
        if m:
            print('        {{ "{0}", &{0} }},'.format(m[2]))
        # Functions defined through a macro
        m = re.search(r'^DEFINE_PUBLIC_TRIVIAL_REF_FUNC\([^,]+,\s*(\w+)\s*\)', line)
        if m:
            print('        {{ "{0}_ref", {0}_ref }},'.format(m[1]))
        m = re.search(r'^DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC\([^,]+,\s*(\w+)\s*,', line)
        if m:
            print('        {{ "{0}_unref", {0}_unref }},'.format(m[1]))
        m = re.search(r"^DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC\([^,]+,\s*(\w+)\s*,", line)
        if m:
            print('        {{ "{0}_ref", {0}_ref }},'.format(m[1]))
            print('        {{ "{0}_unref", {0}_unref }},'.format(m[1]))

print('''/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
''')

for header in sys.argv[3:]:
    print('#include "{}"'.format(header.split('/')[-1]))

print('''
/* We want to check deprecated symbols too, without complaining */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
''')

print('''
static const struct {
        const char *name;
        const void *symbol;
} symbols_from_sym[] = {''')

with open(sys.argv[1], "r") as f:
    process_sym_file(f)

print('''        {}
}, symbols_from_source[] = {''')

for dirpath, _, filenames in os.walk(sys.argv[2]):
    for filename in filenames:
        with open(os.path.join(dirpath, filename), "r") as f:
            process_source_file(f)

print('''        {}
};

int main(void) {
        size_t i, j;

        puts("From symbol file:");
        for (i = 0; symbols_from_sym[i].name; i++)
                printf("%p: %s\\n", symbols_from_sym[i].symbol, symbols_from_sym[i].name);

        puts("\\nFrom source files:");
        for (j = 0; symbols_from_source[j].name; j++)
                printf("%p: %s\\n", symbols_from_source[j].symbol, symbols_from_source[j].name);

        puts("");
        printf("Found %zu symbols from symbol file.\\n", i);
        printf("Found %zu symbols from source files.\\n", j);

        return i == j ? EXIT_SUCCESS : EXIT_FAILURE;
}''')
