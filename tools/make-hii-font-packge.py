#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import struct
import uuid

parser = argparse.ArgumentParser(
    description='Convert GNU unifont hex dump into EFI HII font package.')
parser.add_argument('--wide',
                    choices=['no', 'convert-narrow', 'yes'],
                    help='Use wide glyphs')
parser.add_argument('input',
                    type=argparse.FileType('r'),
                    help='GNU unifont hex dump')
parser.add_argument('output',
                    help='output file',
                    type=argparse.FileType('wb'))
args = parser.parse_args()

# GNU unifont is 8x16, UEFI console fonts are 8x19, so we just add some padding.
NARROW_GLYPH_LEN = 32
PADDDING_TOP = 2
PADDDING_BOTTOM = 1

narrow_count = 0
wide_count = 0
narrow_glyphs = bytearray()
wide_glyphs = bytearray()

while (line := args.input.readline().strip()):
    (code_point, glyph) = line.split(':')
    code_point = int(code_point, 16)

    # Skip ASCII control chars and anything outside BMP (UEFI is UCS-2 only).
    if code_point < 0x20 or code_point > 0xFFFF:
        continue

    is_narrow = len(glyph) == NARROW_GLYPH_LEN

    if is_narrow or args.wide == 'convert-narrow':
        # EFI_NARROW_GLYPH (unicode weight, attributes)
        narrow_glyphs += struct.pack('<HB', code_point, 0)

        for i in range(0, PADDDING_TOP):
            narrow_glyphs += struct.pack('<B', 0)

        if is_narrow:
            for i in range(0, len(glyph), 2):
                narrow_glyphs += struct.pack('<B', int(glyph[i:i+2], 16))
        else:
            for i in range(0, len(glyph), 4):
                col1 = int(glyph[i:i+2], 16)
                col2 = int(glyph[i+2:i+4], 16)

                comb = 0
                if col1 & 0b11000000:
                    comb |= 0b10000000
                if col1 & 0b00110000:
                    comb |= 0b01000000
                if col1 & 0b00001100:
                    comb |= 0b00100000
                if col1 & 0b00000011:
                    comb |= 0b00010000
                if col2 & 0b11000000:
                    comb |= 0b00001000
                if col2 & 0b00110000:
                    comb |= 0b00000100
                if col2 & 0b00001100:
                    comb |= 0b00000010
                if col2 & 0b00000011:
                    comb |= 0b00000001

                narrow_glyphs += struct.pack('<B', comb)

        for i in range(0, PADDDING_BOTTOM):
            narrow_glyphs += struct.pack('<B', 0)

        narrow_count += 1
    elif args.wide == 'yes':
        # EFI_WIDE_GLYPH (unicode weight, attributes)
        wide_glyphs += struct.pack('<HB', code_point, 0x2)

        col1 = bytearray()
        col2 = bytearray()
        for i in range(0, PADDDING_TOP):
            col1 += struct.pack('<B', 0)
            col2 += struct.pack('<B', 0)
        for i in range(0, len(glyph), 4):
            col1 += struct.pack('<B', int(glyph[i:i+2], 16))
            col2 += struct.pack('<B', int(glyph[i+2:i+4], 16))
        for i in range(0, PADDDING_BOTTOM):
            col1 += struct.pack('<B', 0)
            col2 += struct.pack('<B', 0)

        wide_glyphs += col1
        wide_glyphs += col2
        wide_glyphs += struct.pack('3B', 0, 0, 0)  # EFI_WIDE_GLYPH Padding
        wide_count += 1

# A simple HII font package has this layout:
#
# struct _packed_ HiiPackage {
#     struct _packed_ EFI_HII_PACKAGE_LIST_HEADER {
#         EFI_GUID PackageListGuid;
#         uint32_t PackagLength;
#     };
#
#     struct _packed_ EFI_HII_SIMPLE_FONT_PACKAGE_HDR {
#         struct _packed_  EFI_HII_PACKAGE_HEADER {
#             uint32_t Length:24;
#             uint32_t Type:8;
#         } Header;
#
#         uint16_t NumberOfNarrowGlyphs;
#         uint16_t NumberOfWideGlyphs;
#
#         struct _packed_ EFI_NARROW_GLYPH {
#             char16_t UnicodeWeight;
#             uint8_t Attributes;
#             uint8_t GlyphCol1[19];
#         } NarrowGlyphs[];
#
#         struct _packed_ EFI_WIDE_GLYPH {
#             char16_t UnicodeWeight;
#             uint8_t Attributes;
#             uint8_t GlyphCol1[19];
#             uint8_t GlyphCol2[19];
#             uint8_t Pad[3];
#         } WideGlyphs[];
#     };
#
#     struct _packed_ EFI_HII_PACKAGE_HEADER {
#         uint32_t Length:24;
#         uint32_t Type:8;
#     } End;
# };

font_len = 8 + len(narrow_glyphs) + len(wide_glyphs)

# PackageListGuid
hii = uuid.UUID('{07aec0e7-f931-4ba9-b3fa-845b2e2c2833}').bytes_le

hii += struct.pack('<IIHH',
                   font_len + 24,  # PackagLength
                   font_len | (0x07 << 24),  # Header
                   narrow_count,  # NumberOfNarrowGlyphs
                   wide_count,  # NumberOfWideGlyphs
                   )

hii += narrow_glyphs  # NarrowGlyphs[]
hii += wide_glyphs  # WideGlyphs[]

hii += struct.pack('<I', 4 | (0xDF << 24))  # End

args.output.write(hii)
