#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Note: the no-value-for-parameter here is expected, as the click module
#       decorators modify function arguments which pylint doesn't know
# pylint: disable=no-value-for-parameter

"""
A program to parse auxv (e.g. /proc/self/auxv).

By default, current arch is assumed, but options can be used to override the
endianness and word size.
"""

import struct

import click

# From /usr/include/elf.h
AT_AUXV = {
    'AT_NULL' :          0,              # End of vector
    'AT_IGNORE' :        1,              # Entry should be ignored
    'AT_EXECFD' :        2,              # File descriptor of program
    'AT_PHDR' :          3,              # Program headers for program
    'AT_PHENT' :         4,              # Size of program header entry
    'AT_PHNUM' :         5,              # Number of program headers
    'AT_PAGESZ' :        6,              # System page size
    'AT_BASE' :          7,              # Base address of interpreter
    'AT_FLAGS' :         8,              # Flags
    'AT_ENTRY' :         9,              # Entry point of program
    'AT_NOTELF' :        10,             # Program is not ELF
    'AT_UID' :           11,             # Real uid
    'AT_EUID' :          12,             # Effective uid
    'AT_GID' :           13,             # Real gid
    'AT_EGID' :          14,             # Effective gid
    'AT_CLKTCK' :        17,             # Frequency of times()

    # Some more special a_type values describing the hardware.
    'AT_PLATFORM' :      15,             # String identifying platform.
    'AT_HWCAP' :         16,             # Machine-dependent hints about processor capabilities.

    # This entry gives some information about the FPU initialization performed by the kernel.
    'AT_FPUCW' :         18,             # Used FPU control word.

    # Cache block sizes.
    'AT_DCACHEBSIZE' :   19,             # Data cache block size.
    'AT_ICACHEBSIZE' :   20,             # Instruction cache block size.
    'AT_UCACHEBSIZE' :   21,             # Unified cache block size.

    # A special ignored value for PPC, used by the kernel to control the
    # interpretation of the AUXV. Must be > 16.
    'AT_IGNOREPPC' :     22,             # Entry should be ignored.

    'AT_SECURE' :        23,             # Boolean, was exec setuid-like?

    'AT_BASE_PLATFORM' : 24,             # String identifying real platforms.

    'AT_RANDOM' :        25,             # Address of 16 random bytes.

    'AT_HWCAP2' :        26,             # More machine-dependent hints about processor capabilities.

    'AT_EXECFN' :        31,             # Filename of executable.

    # Pointer to the global system page used for system calls and other nice things.
    'AT_SYSINFO' :       32,
    'AT_SYSINFO_EHDR' :  33,

    # Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
    # log2 of line size; mask those to get cache size.
    'AT_L1I_CACHESHAPE' :    34,
    'AT_L1D_CACHESHAPE' :    35,
    'AT_L2_CACHESHAPE' :     36,
    'AT_L3_CACHESHAPE' :     37,

    # Shapes of the caches, with more room to describe them.
    # GEOMETRY are comprised of cache line size in bytes in the bottom 16 bits
    # and the cache associativity in the next 16 bits.
    'AT_L1I_CACHESIZE' :     40,
    'AT_L1I_CACHEGEOMETRY' : 41,
    'AT_L1D_CACHESIZE' :     42,
    'AT_L1D_CACHEGEOMETRY' : 43,
    'AT_L2_CACHESIZE' :      44,
    'AT_L2_CACHEGEOMETRY' :  45,
    'AT_L3_CACHESIZE'     :  46,
    'AT_L3_CACHEGEOMETRY' :  47,

    'AT_MINSIGSTKSZ'      :  51,         # Stack needed for signal delivery
}
AT_AUXV_NAMES = {v:k for k,v in AT_AUXV.items()}

@click.command(help=__doc__)
@click.option('-b', '--big-endian', 'endian',
              flag_value='>',
              help='Input is big-endian')
@click.option('-l', '--little-endian', 'endian',
              flag_value='<',
              help='Input is little-endian')
@click.option('-3', '--32', 'field_width',
              flag_value=32,
              help='Input is 32-bit')
@click.option('-6', '--64', 'field_width',
              flag_value=64,
              help='Input is 64-bit')
@click.argument('file',
                type=click.File(mode='rb'))
def dump(endian, field_width, file):
    data = file.read()

    if field_width is None:
        field_width = struct.calcsize('P') * 8
    if endian is None:
        endian = '@'

    width = {32:'II', 64:'QQ'}[field_width]

    format_str = f'{endian}{width}'
    print(f'# {format_str=}')

    seen_null = False

    for item in struct.iter_unpack(format_str, data):
        key, val = item
        name = AT_AUXV_NAMES.get(key, f'unknown ({key})')
        if name.endswith(('UID', 'GID')):
            pref, fmt = '', 'd'
        else:
            pref, fmt = '0x', 'x'

        if seen_null:
            print('# trailing garbage after AT_NULL')

        print(f'{name:18} = {pref}{val:{fmt}}')

        if name == 'AT_NULL':
            seen_null = True

    if not seen_null:
        print('# array not terminated with AT_NULL')

if __name__ == '__main__':
    dump()
