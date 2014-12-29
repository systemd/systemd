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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "sparse-endian.h"
#include "util.h"

typedef struct unifont_header unifont_header;
typedef struct unifont_glyph_header unifont_glyph_header;

/*
 * Unifont: On-disk data
 * Conventional font-formats have the problem that you have to pre-render each
 * glyph before you can use it. If you just need one glyph, you have to parse
 * the font-file until you found that glyph.
 * GNU-Unifont is a bitmap font with very good Unicode coverage. All glyphs are
 * (n*8)x16 bitmaps. Our on-disk data stores all those glyphs pre-compiled with
 * fixed offsets. Therefore, the font-file can be mmap()ed and all glyphs can
 * be accessed in O(1) (because all glyphs have the same size and thus their
 * offsets can be easily computed). This guarantees, that the kernel only loads
 * the pages that are really accessed. Thus, we have a far lower overhead than
 * traditional font-formats like BDF. Furthermore, the backing file is read-only
 * and can be shared in memory between multiple users.
 *
 * The binary-format starts with a fixed header:
 *
 *      | 2bytes | 2bytes | 2bytes | 2bytes |
 *
 *      +-----------------------------------+
 *      |             SIGNATURE             |   8 bytes
 *      +-----------------+-----------------+
 *      |  COMPAT FLAGS   | INCOMPAT FLAGS  |   8 bytes
 *      +-----------------+--------+--------+
 *      |   HEADER SIZE   |GH-SIZE |G-STRIDE|   8 bytes
 *      +-----------------+--------+--------+
 *      |          GLYPH BODY SIZE          |   8 bytes
 *      +-----------------------------------+
 *
 *  * The 8 bytes signature must be set to the ASCII string "DVDHRMUF".
 *  * The 4 bytes compatible-flags field contains flags for new features that
 *    might be added in the future and which are compatible to older parsers.
 *  * The 4 bytes incompatible-flags field contains flags for new features that
 *    might be added in the future and which are incompatible to old parses.
 *    Thus, if you encounter an unknown bit set, you must abort!
 *  * The 4 bytes header-size field contains the size of the header in bytes. It
 *    must be at least 32 (the size of this fixed header). If new features are
 *    added, it might be increased. It can also be used to add padding to the
 *    end of the header.
 *  * The 2 bytes glyph-header-size field specifies the size of each glyph
 *    header in bytes (see below).
 *  * The 2 bytes glyph-stride field specifies the stride of each line of glyph
 *    data in "bytes per line".
 *  * The 8 byte glyph-body-size field defines the size of each glyph body in
 *    bytes.
 *
 * After the header, the file can contain padding bytes, depending on the
 * header-size field. Everything beyond the header+padding is treated as a big
 * array of glyphs. Each glyph looks like this:
 *
 *      |              1 byte               |
 *
 *      +-----------------------------------+
 *      |               WIDTH               |   1 byte
 *      +-----------------------------------+
 *      ~              PADDING              ~
 *      +-----------------------------------+
 *      ~                                   ~
 *      ~                                   ~
 *      ~                DATA               ~
 *      ~                                   ~
 *      ~                                   ~
 *      +-----------------------------------+
 *
 *  * The first byte specifies the width of the glyph. If it is 0, the glyph
 *    must be treated as non-existent.
 *    All glyphs are "8*n" pixels wide and "16" pixels high. The width-field
 *    specifies the width multiplier "n".
 *  * After the width field padding might be added. This depends on the global
 *    glyph-header-size field. It defines the total size of each glyph-header.
 *    After the glyph-header+padding, the data-field starts.
 *  * The data-field contains a byte-array of bitmap data. The array is always
 *    as big as specified in the global glyph-body-size header field. This might
 *    include padding.
 *    The array contains all 16 lines of bitmap information for that glyph. The
 *    stride is given in the global glyph-stride header field. This can be used
 *    to add padding after each line.
 *    Each line is encoded as 1 bit per pixel bitmap. That is, each byte encodes
 *    data for 8 pixels (left most pixel is encoded in the LSB, right most pixel
 *    in the MSB). The width field defines the number of bytes valid per line.
 *    For width==1, you need 1 byte to encode the 8 pixels. The stride defines
 *    where the encoding of the next line starts.
 *    Any data beyond the 16th line is padding and must be ignored.
 */

/* path to binary file */
#define UNIFONT_PATH "/usr/share/systemd/unifont-glyph-array.bin"

/* header-size of version 1 */
#define UNIFONT_HEADER_SIZE_MIN 32

struct unifont_header {
        /* fields available in version 1 */
        uint8_t signature[8];
        le32_t compatible_flags;
        le32_t incompatible_flags;
        le32_t header_size;
        le16_t glyph_header_size;
        le16_t glyph_stride;
        le64_t glyph_body_size;
} _packed_;

struct unifont_glyph_header {
        /* fields available in version 1 */
        uint8_t width;
} _packed_;
