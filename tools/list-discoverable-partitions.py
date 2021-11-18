#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import sys
import uuid

HEADER = f'''\
<!-- generated with {sys.argv[0]} -->
| Partition Type UUID | Name | Allowed File Systems | Explanation |
|---------------------|------|----------------------|-------------|
'''

ARCHITECTURES = {
    'ALPHA':       'Alpha',
    'ARC':         'ARC',
    'ARM':         '32-bit ARM',
    'ARM64':       '64-bit ARM/AArch64',
    'IA64':        'Itanium/IA-64',
    'LOONGARCH64': 'LoongArch 64-bit',
    'POWERPC':     '32-bit PowerPC',
    'POWERPC64':   '64-bit PowerPC BigEndian',
    'POWERPC64LE': '64-bit PowerPC LittleEndian',
    'RISCV32':     'RISC-V 32-bit',
    'RISCV64':     'RISC-V 64-bit',
    'S390':        's390',
    'S390X':       's390x',
    'TILEGX':      'TILE-Gx',
    'X86':         'x86',
    'X86_64':      'amd64/x86_64',
}

TYPES = {
    'ROOT' :            'Root Partition',
    'ROOT_VERITY' :     'Root Verity Partition',
    'ROOT_VERITY_SIG' : 'Root Verity Signature Partition',
    'USR' :             '`/usr/` Partition',
    'USR_VERITY' :      '`/usr/` Verity Partition',
    'USR_VERITY_SIG' :  '`/usr/` Verity Signature Partition',
    'ESP':              'EFI System Partition',
    'SRV':              'Server Data Partition',
    'VAR':              'Variable Data Partition',
    'TMP':              'Temporary Data Partition',
    'SWAP':             'Swap',
    'HOME':             'Home Partition',
    'USER_HOME':        'Per-user Home Partition',
    'LINUX_GENERIC':    'Generic Linux Data Partition',
    'XBOOTLDR':         'Extended Boot Loader Partition',
}

def extract(file):
    for line in file:
        # print(line)
        m = re.match(r'^#define\s+GPT_(.*SD_ID128_MAKE.*)', line)
        if not m:
            continue

        if m2 := re.match(r'^(ROOT|USR)_([A-Z0-9]+|X86_64)(|_VERITY|_VERITY_SIG)\s+SD_ID128_MAKE\((.*)\)', m.group(1)):
            type, arch, suffix, u = m2.groups()
            u = uuid.UUID(u.replace(',', ''))
            assert arch in ARCHITECTURES
            type = f'{type}{suffix}'
            assert type in TYPES

            yield type, arch, u

        elif m2 := re.match(r'(\w+)\s+SD_ID128_MAKE\((.*)\)', m.group(1)):
            type, u = m2.groups()
            u = uuid.UUID(u.replace(',', ''))
            yield type, None, u

        else:
            raise Exception(f'Failed to match: {m.group(1)}')

def generate(defines):
    prevtype = None

    print(HEADER, end='')

    mores = []

    for type, arch, uuid in defines:
        tdesc = TYPES[type]
        adesc = '' if arch is None else f' ({ARCHITECTURES[arch]})'

        if type != prevtype:
            prevtype = type
            link = tdesc.replace('`', '')
            morea = f'[{link}]'
            moreb = f'[{link} more]'
            mores += [morea, moreb]
        else:
            morea = moreb = 'ditto'

        print(f'| _{tdesc}{adesc}_ | `{uuid}` | {morea} | {moreb} |')

    # print the anchors to make it easier to fill in
    for more in mores:
        print(f'{more}:')

if __name__ == '__main__':
    known = extract(sys.stdin)
    generate(known)
