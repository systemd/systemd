/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/*
 * VTE Character Sets
 * These are predefined charactersets that can be loaded into GL and GR. By
 * default we use unicode_lower and unicode_upper, that is, both sets have the
 * exact unicode mapping. unicode_lower is effectively ASCII and unicode_upper
 * as defined by the unicode standard (I guess, ISO 8859-1).
 * Several other character sets are defined here. However, all of them are
 * limited to the 96 character space of GL or GR. Everything beyond GR (which
 * was not supported by the classic VTs by DEC but is available in VT emulators
 * that support unicode/UTF8) is always mapped to unicode and cannot be changed
 * by these character sets. Even mapping GL and GR is only available for
 * backwards compatibility as new applications can use the Unicode functionality
 * of the VTE.
 *
 * Moreover, mapping GR is almost unnecessary to support. In fact, Unicode UTF-8
 * support in VTE works by reading every incoming data as UTF-8 stream. This
 * maps GL/ASCII to ASCII, as UTF-8 is backwards compatible to ASCII, however,
 * everything that has the 8th bit set is a >=2-byte haracter in UTF-8. That is,
 * this is in no way backwards compatible to >=VT220 8bit support. Therefore, if
 * someone maps a character set into GR and wants to use them with this VTE,
 * then they must already send UTF-8 characters to use GR (all GR characters are
 * 8-bits). Hence, they can easily also send the correct UTF-8 character for the
 * unicode mapping.
 * The only advantage is that most characters in many sets are 3-byte UTF-8
 * characters and by mapping the set into GR/GL you can use 2 or 1 byte UTF-8
 * characters which saves bandwidth.
 * Another reason is, if you have older applications that use the VT220 8-bit
 * support and you put a ASCII/8bit-extension to UTF-8 converter in between, you
 * need these mappings to have the application behave correctly if it uses GL/GR
 * mappings extensively.
 *
 * Anyway, we support GL/GR mappings so here are the most commonly used maps as
 * defined by Unicode-standard, DEC-private maps and other famous charmaps.
 *
 * Characters 1-32 are always the control characters (part of CL) and cannot be
 * mapped. Characters 34-127 (94 characters) are part of GL and can be mapped.
 * Characters 33 and 128 are not part of GL and always mapped by the VTE.
 * However, for GR they can be mapped differently (96 chars) so we have to
 * include them. The mapper has to take care not to use them in GL.
 */

#include "term-internal.h"

/*
 * Lower Unicode character set. This maps the characters to the basic ASCII
 * characters 33-126. These are all graphics characters defined in ASCII.
 */
term_charset term_unicode_lower = {
        [0] = 32,
        [1] = 33,
        [2] = 34,
        [3] = 35,
        [4] = 36,
        [5] = 37,
        [6] = 38,
        [7] = 39,
        [8] = 40,
        [9] = 41,
        [10] = 42,
        [11] = 43,
        [12] = 44,
        [13] = 45,
        [14] = 46,
        [15] = 47,
        [16] = 48,
        [17] = 49,
        [18] = 50,
        [19] = 51,
        [20] = 52,
        [21] = 53,
        [22] = 54,
        [23] = 55,
        [24] = 56,
        [25] = 57,
        [26] = 58,
        [27] = 59,
        [28] = 60,
        [29] = 61,
        [30] = 62,
        [31] = 63,
        [32] = 64,
        [33] = 65,
        [34] = 66,
        [35] = 67,
        [36] = 68,
        [37] = 69,
        [38] = 70,
        [39] = 71,
        [40] = 72,
        [41] = 73,
        [42] = 74,
        [43] = 75,
        [44] = 76,
        [45] = 77,
        [46] = 78,
        [47] = 79,
        [48] = 80,
        [49] = 81,
        [50] = 82,
        [51] = 83,
        [52] = 84,
        [53] = 85,
        [54] = 86,
        [55] = 87,
        [56] = 88,
        [57] = 89,
        [58] = 90,
        [59] = 91,
        [60] = 92,
        [61] = 93,
        [62] = 94,
        [63] = 95,
        [64] = 96,
        [65] = 97,
        [66] = 98,
        [67] = 99,
        [68] = 100,
        [69] = 101,
        [70] = 102,
        [71] = 103,
        [72] = 104,
        [73] = 105,
        [74] = 106,
        [75] = 107,
        [76] = 108,
        [77] = 109,
        [78] = 110,
        [79] = 111,
        [80] = 112,
        [81] = 113,
        [82] = 114,
        [83] = 115,
        [84] = 116,
        [85] = 117,
        [86] = 118,
        [87] = 119,
        [88] = 120,
        [89] = 121,
        [90] = 122,
        [91] = 123,
        [92] = 124,
        [93] = 125,
        [94] = 126,
        [95] = 127,
};

/*
 * Upper Unicode Table
 * This maps all characters to the upper unicode characters 161-254. These are
 * not compatible to any older 8 bit character sets. See the Unicode standard
 * for the definitions of each symbol.
 */
term_charset term_unicode_upper = {
        [0] = 160,
        [1] = 161,
        [2] = 162,
        [3] = 163,
        [4] = 164,
        [5] = 165,
        [6] = 166,
        [7] = 167,
        [8] = 168,
        [9] = 169,
        [10] = 170,
        [11] = 171,
        [12] = 172,
        [13] = 173,
        [14] = 174,
        [15] = 175,
        [16] = 176,
        [17] = 177,
        [18] = 178,
        [19] = 179,
        [20] = 180,
        [21] = 181,
        [22] = 182,
        [23] = 183,
        [24] = 184,
        [25] = 185,
        [26] = 186,
        [27] = 187,
        [28] = 188,
        [29] = 189,
        [30] = 190,
        [31] = 191,
        [32] = 192,
        [33] = 193,
        [34] = 194,
        [35] = 195,
        [36] = 196,
        [37] = 197,
        [38] = 198,
        [39] = 199,
        [40] = 200,
        [41] = 201,
        [42] = 202,
        [43] = 203,
        [44] = 204,
        [45] = 205,
        [46] = 206,
        [47] = 207,
        [48] = 208,
        [49] = 209,
        [50] = 210,
        [51] = 211,
        [52] = 212,
        [53] = 213,
        [54] = 214,
        [55] = 215,
        [56] = 216,
        [57] = 217,
        [58] = 218,
        [59] = 219,
        [60] = 220,
        [61] = 221,
        [62] = 222,
        [63] = 223,
        [64] = 224,
        [65] = 225,
        [66] = 226,
        [67] = 227,
        [68] = 228,
        [69] = 229,
        [70] = 230,
        [71] = 231,
        [72] = 232,
        [73] = 233,
        [74] = 234,
        [75] = 235,
        [76] = 236,
        [77] = 237,
        [78] = 238,
        [79] = 239,
        [80] = 240,
        [81] = 241,
        [82] = 242,
        [83] = 243,
        [84] = 244,
        [85] = 245,
        [86] = 246,
        [87] = 247,
        [88] = 248,
        [89] = 249,
        [90] = 250,
        [91] = 251,
        [92] = 252,
        [93] = 253,
        [94] = 254,
        [95] = 255,
};

/*
 * The DEC supplemental graphics set. For its definition see here:
 *  http://vt100.net/docs/vt220-rm/table2-3b.html
 * Its basically a mixture of common European symbols that are not part of
 * ASCII. Most often, this is mapped into GR to extend the basci ASCII part.
 *
 * This is very similar to unicode_upper, however, few symbols differ so do not
 * mix them up!
 */
term_charset term_dec_supplemental_graphics = {
        [0] = -1,       /* undefined */
        [1] = 161,
        [2] = 162,
        [3] = 163,
        [4] = 0,
        [5] = 165,
        [6] = 0,
        [7] = 167,
        [8] = 164,
        [9] = 169,
        [10] = 170,
        [11] = 171,
        [12] = 0,
        [13] = 0,
        [14] = 0,
        [15] = 0,
        [16] = 176,
        [17] = 177,
        [18] = 178,
        [19] = 179,
        [20] = 0,
        [21] = 181,
        [22] = 182,
        [23] = 183,
        [24] = 0,
        [25] = 185,
        [26] = 186,
        [27] = 187,
        [28] = 188,
        [29] = 189,
        [30] = 0,
        [31] = 191,
        [32] = 192,
        [33] = 193,
        [34] = 194,
        [35] = 195,
        [36] = 196,
        [37] = 197,
        [38] = 198,
        [39] = 199,
        [40] = 200,
        [41] = 201,
        [42] = 202,
        [43] = 203,
        [44] = 204,
        [45] = 205,
        [46] = 206,
        [47] = 207,
        [48] = 0,
        [49] = 209,
        [50] = 210,
        [51] = 211,
        [52] = 212,
        [53] = 213,
        [54] = 214,
        [55] = 338,
        [56] = 216,
        [57] = 217,
        [58] = 218,
        [59] = 219,
        [60] = 220,
        [61] = 376,
        [62] = 0,
        [63] = 223,
        [64] = 224,
        [65] = 225,
        [66] = 226,
        [67] = 227,
        [68] = 228,
        [69] = 229,
        [70] = 230,
        [71] = 231,
        [72] = 232,
        [73] = 233,
        [74] = 234,
        [75] = 235,
        [76] = 236,
        [77] = 237,
        [78] = 238,
        [79] = 239,
        [80] = 0,
        [81] = 241,
        [82] = 242,
        [83] = 243,
        [84] = 244,
        [85] = 245,
        [86] = 246,
        [87] = 339,
        [88] = 248,
        [89] = 249,
        [90] = 250,
        [91] = 251,
        [92] = 252,
        [93] = 255,
        [94] = 0,
        [95] = -1,       /* undefined */
};

/*
 * DEC special graphics character set. See here for its definition:
 *  http://vt100.net/docs/vt220-rm/table2-4.html
 * This contains several characters to create ASCII drawings and similar. Its
 * commonly mapped into GR to extend the basic ASCII characters.
 *
 * Lower 62 characters map to ASCII 33-64, everything beyond is special and
 * commonly used for ASCII drawings. It depends on the Unicode Standard 3.2 for
 * the extended horizontal scan-line characters 3, 5, 7, and 9.
 */
term_charset term_dec_special_graphics = {
        [0] = -1,       /* undefined */
        [1] = 33,
        [2] = 34,
        [3] = 35,
        [4] = 36,
        [5] = 37,
        [6] = 38,
        [7] = 39,
        [8] = 40,
        [9] = 41,
        [10] = 42,
        [11] = 43,
        [12] = 44,
        [13] = 45,
        [14] = 46,
        [15] = 47,
        [16] = 48,
        [17] = 49,
        [18] = 50,
        [19] = 51,
        [20] = 52,
        [21] = 53,
        [22] = 54,
        [23] = 55,
        [24] = 56,
        [25] = 57,
        [26] = 58,
        [27] = 59,
        [28] = 60,
        [29] = 61,
        [30] = 62,
        [31] = 63,
        [32] = 64,
        [33] = 65,
        [34] = 66,
        [35] = 67,
        [36] = 68,
        [37] = 69,
        [38] = 70,
        [39] = 71,
        [40] = 72,
        [41] = 73,
        [42] = 74,
        [43] = 75,
        [44] = 76,
        [45] = 77,
        [46] = 78,
        [47] = 79,
        [48] = 80,
        [49] = 81,
        [50] = 82,
        [51] = 83,
        [52] = 84,
        [53] = 85,
        [54] = 86,
        [55] = 87,
        [56] = 88,
        [57] = 89,
        [58] = 90,
        [59] = 91,
        [60] = 92,
        [61] = 93,
        [62] = 94,
        [63] = 0,
        [64] = 9830,
        [65] = 9618,
        [66] = 9225,
        [67] = 9228,
        [68] = 9229,
        [69] = 9226,
        [70] = 176,
        [71] = 177,
        [72] = 9252,
        [73] = 9227,
        [74] = 9496,
        [75] = 9488,
        [76] = 9484,
        [77] = 9492,
        [78] = 9532,
        [79] = 9146,
        [80] = 9147,
        [81] = 9472,
        [82] = 9148,
        [83] = 9149,
        [84] = 9500,
        [85] = 9508,
        [86] = 9524,
        [87] = 9516,
        [88] = 9474,
        [89] = 8804,
        [90] = 8805,
        [91] = 960,
        [92] = 8800,
        [93] = 163,
        [94] = 8901,
        [95] = -1,      /* undefined */
};
