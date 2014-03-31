/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2008-2011 Kay Sievers
  Copyright 2012 Lennart Poettering

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

/* Parts of this file are based on the GLIB utf8 validation functions. The
 * original license text follows. */

/* gutf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#include "utf8.h"
#include "util.h"

static inline bool is_unicode_valid(uint32_t ch) {

        if (ch >= 0x110000) /* End of unicode space */
                return false;
        if ((ch & 0xFFFFF800) == 0xD800) /* Reserved area for UTF-16 */
                return false;
        if ((ch >= 0xFDD0) && (ch <= 0xFDEF)) /* Reserved */
                return false;
        if ((ch & 0xFFFE) == 0xFFFE) /* BOM (Byte Order Mark) */
                return false;

        return true;
}

static bool is_unicode_control(uint32_t ch) {

        /*
          0 to ' '-1 is the C0 range.
          DEL=0x7F, and DEL+1 to 0x9F is C1 range.
          '\t' is in C0 range, but more or less harmless and commonly used.
        */

        return (ch < ' ' && ch != '\t' && ch != '\n') ||
                (0x7F <= ch && ch <= 0x9F);
}

/* count of characters used to encode one unicode char */
static int utf8_encoded_expected_len(const char *str) {
        unsigned char c = (unsigned char)str[0];

        if (c < 0x80)
                return 1;
        if ((c & 0xe0) == 0xc0)
                return 2;
        if ((c & 0xf0) == 0xe0)
                return 3;
        if ((c & 0xf8) == 0xf0)
                return 4;
        if ((c & 0xfc) == 0xf8)
                return 5;
        if ((c & 0xfe) == 0xfc)
                return 6;
        return 0;
}

/* decode one unicode char */
int utf8_encoded_to_unichar(const char *str) {
        int unichar;
        int len;
        int i;

        len = utf8_encoded_expected_len(str);
        switch (len) {
        case 1:
                return (int)str[0];
        case 2:
                unichar = str[0] & 0x1f;
                break;
        case 3:
                unichar = (int)str[0] & 0x0f;
                break;
        case 4:
                unichar = (int)str[0] & 0x07;
                break;
        case 5:
                unichar = (int)str[0] & 0x03;
                break;
        case 6:
                unichar = (int)str[0] & 0x01;
                break;
        default:
                return -1;
        }

        for (i = 1; i < len; i++) {
                if (((int)str[i] & 0xc0) != 0x80)
                        return -1;
                unichar <<= 6;
                unichar |= (int)str[i] & 0x3f;
        }

        return unichar;
}

bool utf8_is_printable_newline(const char* str, size_t length, bool newline) {
        const uint8_t *p;

        assert(str);

        for (p = (const uint8_t*) str; length;) {
                int encoded_len = utf8_encoded_valid_unichar((const char *)p);
                int val = utf8_encoded_to_unichar((const char*)p);

                if (encoded_len < 0 || val < 0 || is_unicode_control(val) ||
                    (!newline && val == '\n'))
                        return false;

                length -= encoded_len;
                p += encoded_len;
        }

        return true;
}

const char *utf8_is_valid(const char *str) {
        const uint8_t *p;

        assert(str);

        for (p = (const uint8_t*) str; *p; ) {
                int len;

                len = utf8_encoded_valid_unichar((const char *)p);

                if (len < 0)
                        return NULL;

                p += len;
        }

        return str;
}

char *utf8_escape_invalid(const char *str) {
        char *p, *s;

        assert(str);

        p = s = malloc(strlen(str) * 4 + 1);
        if (!p)
                return NULL;

        while (*str) {
                int len;

                len = utf8_encoded_valid_unichar(str);
                if (len > 0) {
                        s = mempcpy(s, str, len);
                        str += len;
                } else {
                        s = mempcpy(s, UTF8_REPLACEMENT_CHARACTER, strlen(UTF8_REPLACEMENT_CHARACTER));
                        str += 1;
                }
        }
        *s = '\0';

        return p;
}

char *ascii_is_valid(const char *str) {
        const char *p;

        assert(str);

        for (p = str; *p; p++)
                if ((unsigned char) *p >= 128)
                        return NULL;

        return (char*) str;
}

char *utf16_to_utf8(const void *s, size_t length) {
        char *r;
        const uint8_t *f;
        uint8_t *t;

        r = new(char, (length*3+1)/2 + 1);
        if (!r)
                return NULL;

        t = (uint8_t*) r;

        for (f = s; f < (const uint8_t*) s + length; f += 2) {
                uint16_t c;

                c = (f[1] << 8) | f[0];

                if (c == 0) {
                        *t = 0;
                        return r;
                } else if (c < 0x80) {
                        *(t++) = (uint8_t) c;
                } else if (c < 0x800) {
                        *(t++) = (uint8_t) (0xc0 | (c >> 6));
                        *(t++) = (uint8_t) (0x80 | (c & 0x3f));
                } else {
                        *(t++) = (uint8_t) (0xe0 | (c >> 12));
                        *(t++) = (uint8_t) (0x80 | ((c >> 6) & 0x3f));
                        *(t++) = (uint8_t) (0x80 | (c & 0x3f));
                }
        }

        *t = 0;

        return r;
}

/* expected size used to encode one unicode char */
static int utf8_unichar_to_encoded_len(int unichar) {
        if (unichar < 0x80)
                return 1;
        if (unichar < 0x800)
                return 2;
        if (unichar < 0x10000)
                return 3;
        if (unichar < 0x200000)
                return 4;
        if (unichar < 0x4000000)
                return 5;
        return 6;
}

/* validate one encoded unicode char and return its length */
int utf8_encoded_valid_unichar(const char *str) {
        int len;
        int unichar;
        int i;

        len = utf8_encoded_expected_len(str);
        if (len == 0)
                return -1;

        /* ascii is valid */
        if (len == 1)
                return 1;

        /* check if expected encoded chars are available */
        for (i = 0; i < len; i++)
                if ((str[i] & 0x80) != 0x80)
                        return -1;

        unichar = utf8_encoded_to_unichar(str);

        /* check if encoded length matches encoded value */
        if (utf8_unichar_to_encoded_len(unichar) != len)
                return -1;

        /* check if value has valid range */
        if (!is_unicode_valid(unichar))
                return -1;

        return len;
}
