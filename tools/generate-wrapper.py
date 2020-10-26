#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1+

import argparse
import collections
import itertools
import re
import shlex
import subprocess
import sys

# https://stackoverflow.com/a/45866339/405505
FUNC_PATTERN = r'(?:^|;)\s*(?:(?:extern)\s+)?(?!else|typedef|return)((?:__attribute__\s*\(\((?:const|pure)\)\)\s+)?(?:const\s+)?(?:struct\s+)?\w+(?:\s+|\s*\*?\s*))(\w+)\s*\(([^0]+)\)\s*'

Definition = collections.namedtuple('Definition', 'line return_type name arguments')

def merge_lines(lines):
    lines = (line for line in lines
             if line and not line[0] == '#')
    split = ' '.join(lines).split(';')

    level = 0
    acc = ''
    for line in split:
        level += (len(list(filter(lambda x: x in '([{', line))) -
                  len(list(filter(lambda x: x in ')]}', line))))
        acc += line
        if level == 0:
            if acc:
                # print(f'--- {acc!r}')
                yield acc
            acc = ''

def extract(opts):
    symbols = set(opts.symbols)

    cmd = shlex.split(opts.cpp)
    for define in opts.define:
        cmd += ['--define', define]
    for source in opts.source:
        cmd += ['-include', source]
    cmd += ['-']
    print(f"/* Generated from '{' '.join(cmd)} </dev/null' */")
    text = subprocess.check_output(cmd, stdin=subprocess.DEVNULL, text=True)

    lines = merge_lines(text.splitlines())

    for line in lines:
        m = re.match(FUNC_PATTERN, line)
        if m and m.group(2) in opts.symbols:
            yield Definition(line, m.group(1), m.group(2), m.group(3))
            symbols.remove(m.group(2))

    if symbols:
        raise ValueError(f"some symbols were not matched: {', '.join(symbols)}")

WRAPPER_TYPE = '''\
typedef {return_type} (*wrap_type_{name})({arguments});
'''
WRAPPER_FUNC = '''\
static wrap_type_{name} wrap_res_{name}(void) {{ return {name}; }}
{return_type} wrap_{name}({arguments}) __attribute__ ((ifunc ("wrap_res_{name}")));
'''

def generate(opts, functions):
    if opts.header:
        print(f'#include "{opts.header}"')
    else:
        print( '#pragma once')
        for define in opts.define:
            print(f"#define {define.replace('=', ' ')}")
        for source in opts.source:
            print(f'#include <{source}>')

    for func in functions:
        f = WRAPPER_FUNC if opts.header else WRAPPER_TYPE
        print(f.format(name=func.name,
                       return_type=func.return_type,
                       arguments=func.arguments))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--cpp', default='cpp -E')
    p.add_argument('--define', action='append', default=[],
                   help='Pass a define definition to the compiler')
    p.add_argument('--header',
                   help='Include specifier header and generate C code')
    p.add_argument('--source', action='append', default=[],
                   help='Scape this header')
    p.add_argument('symbols', nargs='+')
    opts = p.parse_args()
    return opts

if __name__ == '__main__':
    opts = parse_args()

    functions = extract(opts)
    generate(opts, functions)
