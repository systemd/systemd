#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# ruff: noqa: E501 UP015

import os
import re
import sys
from pathlib import Path
from typing import IO


def process_sym_file(file: IO[str]) -> None:
    for line in file:
        m = re.search(r'^ +([a-zA-Z0-9_]+);', line)
        if m:
            if m[1] == 'sd_bus_object_vtable_format':
                print(f'        {{ "{m[1]}", &{m[1]} }},')
            else:
                print(f'        {{ "{m[1]}", {m[1]} }},')


def process_header_file(file: IO[str]) -> str:
    text = ''

    for line in file:
        if (
            line.startswith('#')
            or line.startswith('typedef')
            or line.startswith('extern "C"')
            or line.startswith('__extension__')
            or line.startswith('/*')
            or ' __inline__ ' in line
            or re.search(r'^\s+', line)
        ):
            continue

        m = re.search(r'^(.*)\s*__attribute__', line)
        if m:
            line = m[1]

        m = re.search(r'^(.*)\s*_sd_printf_', line)
        if m:
            line = m[1]

        # Functions
        m = re.search(r'^(\S+\s+)+\**(\w+)\s*\(', line)
        if m:
            text += f'        {{ "{m[2]}", {m[2]} }},\n'
            continue

        # Variables
        m = re.search(r'^extern\s', line)
        if m:
            n = line.split()[-1].rstrip(';')
            text += f'        {{ "{n}", &{n} }},\n'
            continue

        # Functions defined by macro
        m = re.search(r'_SD_DEFINE_POINTER_CLEANUP_FUNC\(\w+,\s*(\w+)\)', line)
        if m:
            text += f'        {{ "{m[1]}", {m[1]} }},\n'
            continue

        # Functions declared by ref/unref macros
        m = re.search(r'_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC\((\w+)\)', line)
        if m:
            text += f'        {{ "{m[1]}_ref", {m[1]}_ref }},\n'
            text += f'        {{ "{m[1]}_unref", {m[1]}_unref }},\n'
            continue

        m = re.search(r'_SD_DECLARE_TRIVIAL_REF_FUNC\((\w+)\)', line)
        if m:
            text += f'        {{ "{m[1]}_ref", {m[1]}_ref }},\n'
            continue

        m = re.search(r'_SD_DECLARE_TRIVIAL_UNREF_FUNC\((\w+)\)', line)
        if m:
            text += f'        {{ "{m[1]}_unref", {m[1]}_unref }},\n'
            continue

    return text


def process_source_file(file: IO[str]) -> None:
    for line in file:
        # Functions
        m = re.search(r'^_public_\s+(\S+\s+)+\**(\w+)\s*\(', line)
        if m:
            print(f'        {{ "{m[2]}", {m[2]} }},')
            continue

        # Variables
        m = re.search(r'^_public_\s+(\S+\s+)+\**(\w+)\s*=', line)
        if m:
            print(f'        {{ "{m[2]}", &{m[2]} }},')
            continue

        # Functions defined through a macro
        m = re.search(r'^DEFINE_PUBLIC_TRIVIAL_REF_FUNC\([^,]+,\s*(\w+)\s*\)', line)
        if m:
            print(f'        {{ "{m[1]}_ref", {m[1]}_ref }},')
            continue

        m = re.search(r'^DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC\([^,]+,\s*(\w+)\s*,', line)
        if m:
            print(f'        {{ "{m[1]}_unref", {m[1]}_unref }},')
            continue

        m = re.search(r'^DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC\([^,]+,\s*(\w+)\s*,', line)
        if m:
            print(f'        {{ "{m[1]}_ref", {m[1]}_ref }},')
            print(f'        {{ "{m[1]}_unref", {m[1]}_unref }},')
            continue

        m = re.search(r'^_DEFINE_STRING_TABLE_LOOKUP\((\w+),\s*\w+,\s*_public_\s*\)', line)
        if m:
            print(f'        {{ "{m[1]}_from_string", {m[1]}_from_string }},')
            print(f'        {{ "{m[1]}_to_string", {m[1]}_to_string }},')
            continue


print("""/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

""")

for header in sys.argv[3:]:
    with open(header, 'r') as f:
        if process_header_file(f):
            print('#include "{}"'.format(header.split('/')[-1]))

print("""
/* We want to check deprecated symbols too, without complaining */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
""")

print("""
struct symbol {
        const char *name;
        const void *symbol;
};
static struct symbol symbols_from_sym[] = {""")

with open(sys.argv[1], 'r') as f:
    process_sym_file(f)

print("""        {}
}, symbols_from_header[] = {""")

for header in sys.argv[3:]:
    with open(header, 'r') as f:
        print(process_header_file(f), end='')

print("""        {}
}, symbols_from_source[] = {""")

for dirpath, _, filenames in sorted(os.walk(sys.argv[2])):
    for filename in sorted(filenames):
        if not filename.endswith('.c') and not filename.endswith('.h'):
            continue
        p = Path(dirpath) / filename
        if p.is_symlink():
            continue
        with p.open('rt') as f:
            process_source_file(f)

print("""        {}
};

static int sort_callback(const void *a, const void *b) {
        const struct symbol *x = a, *y = b;
        return strcmp(x->name, y->name);
}

int main(void) {
        size_t size = sizeof(symbols_from_sym[0]),
                n_sym = sizeof(symbols_from_sym)/sizeof(symbols_from_sym[0]) - 1,
                n_header = sizeof(symbols_from_header)/sizeof(symbols_from_header[0]) - 1,
                n_source = sizeof(symbols_from_source)/sizeof(symbols_from_source[0]) - 1;

        qsort(symbols_from_sym, n_sym, size, sort_callback);
        qsort(symbols_from_header, n_header, size, sort_callback);
        qsort(symbols_from_source, n_source, size, sort_callback);

        puts("From symbol file:");
        for (size_t i = 0; i < n_sym; i++)
                printf("%p: %s\\n", symbols_from_sym[i].symbol, symbols_from_sym[i].name);

        puts("\\nFrom header files:");
        for (size_t i = 0; i < n_header; i++)
                printf("%p: %s\\n", symbols_from_header[i].symbol, symbols_from_header[i].name);

        puts("\\nFrom source files:");
        for (size_t i = 0; i < n_source; i++)
                printf("%p: %s\\n", symbols_from_source[i].symbol, symbols_from_source[i].name);

        puts("");
        printf("Found %zu symbols from symbol file.\\n", n_sym);
        printf("Found %zu symbols from header files.\\n", n_header);
        printf("Found %zu symbols from source files.\\n", n_source);

        unsigned n_error = 0;

        for (size_t i = 0; i < n_sym; i++) {
                if (!bsearch(symbols_from_sym+i, symbols_from_header, n_header, size, sort_callback)) {
                        printf("Found in symbol file, but not in headers: %s\\n", symbols_from_sym[i].name);
                        n_error++;
                }
                if (!bsearch(symbols_from_sym+i, symbols_from_source, n_source, size, sort_callback)) {
                        printf("Found in symbol file, but not in sources: %s\\n", symbols_from_sym[i].name);
                        n_error++;
                }
        }

        for (size_t i = 0; i < n_header; i++) {
                if (!bsearch(symbols_from_header+i, symbols_from_sym, n_sym, size, sort_callback)) {
                        printf("Found in header file, but not in symbol file: %s\\n", symbols_from_header[i].name);
                        n_error++;
                }
                if (!bsearch(symbols_from_header+i, symbols_from_source, n_source, size, sort_callback)) {
                        printf("Found in header file, but not in sources: %s\\n", symbols_from_header[i].name);
                        n_error++;
                }
        }

        for (size_t i = 0; i < n_source; i++) {
                if (!bsearch(symbols_from_source+i, symbols_from_sym, n_sym, size, sort_callback)) {
                        printf("Found in source file, but not in symbol file: %s\\n", symbols_from_source[i].name);
                        n_error++;
                }
                if (!bsearch(symbols_from_source+i, symbols_from_header, n_header, size, sort_callback)) {
                        printf("Found in source file, but not in header: %s\\n", symbols_from_source[i].name);
                        n_error++;
                }
        }

        return n_error == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}""")
