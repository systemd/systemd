#  -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2013-2014 David Herrmann <dh.herrmann@gmail.com>
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

#
# Parse a unifont.hex file and produce a compressed binary-format.
#

from __future__ import print_function
import re
import sys
import fileinput
import struct

#
# Write "bits" array as binary output.
#


write = getattr(sys.stdout, 'buffer', sys.stdout).write

def write_bin_entry(entry):
    l = len(entry)
    if l != 32 and l != 64:
        entry = "0" * 64
        l = 0
    elif l < 64:
        entry += "0" * (64 - l)

    write(struct.pack('B', int(l / 32)))  # width
    write(struct.pack('B', 0))            # padding
    write(struct.pack('H', 0))            # padding
    write(struct.pack('I', 0))            # padding

    i = 0
    for j in range(0, 16):
        for k in range(0, 2):
            if l <= k * 16 * 2:
                c = 0
            else:
                c = int(entry[i:i+2], 16)
                i += 2

            write(struct.pack('B', c))

def write_bin(bits):
    write(struct.pack('B', 0x44))         # ASCII: 'D'
    write(struct.pack('B', 0x56))         # ASCII: 'V'
    write(struct.pack('B', 0x44))         # ASCII: 'D'
    write(struct.pack('B', 0x48))         # ASCII: 'H'
    write(struct.pack('B', 0x52))         # ASCII: 'R'
    write(struct.pack('B', 0x4d))         # ASCII: 'M'
    write(struct.pack('B', 0x55))         # ASCII: 'U'
    write(struct.pack('B', 0x46))         # ASCII: 'F'
    write(struct.pack('<I', 0))           # compatible-flags
    write(struct.pack('<I', 0))           # incompatible-flags
    write(struct.pack('<I', 32))          # header-size
    write(struct.pack('<H', 8))           # glyph-header-size
    write(struct.pack('<H', 2))           # glyph-stride
    write(struct.pack('<Q', 32))          # glyph-body-size

    # write glyphs
    for idx in range(len(bits)):
        write_bin_entry(bits[idx])

#
# Parse hex file into "bits" array
#

def parse_hex_line(bits, line):
    m = re.match(r"^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$", line)
    if m == None:
        return

    idx = int(m.group(1), 16)
    val = m.group(2)

    # insert skipped lines
    for i in range(len(bits), idx):
        bits.append("")

    bits.insert(idx, val)

def parse_hex():
    bits = []

    for line in sys.stdin:
        if not line:
            continue
        if line.startswith("#"):
            continue

        parse_hex_line(bits, line)

    return bits

#
# In normal mode we simply read line by line from standard-input and write the
# binary-file to standard-output.
#

if __name__ == "__main__":
    bits = parse_hex()
    write_bin(bits)
