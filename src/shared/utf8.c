/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

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

/* This file is based on the GLIB utf8 validation functions. The
 * original license text follows. */

/* gutf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.         See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#include "utf8.h"

#define FILTER_CHAR '_'

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

static inline bool is_continuation_char(uint8_t ch) {
        if ((ch & 0xc0) != 0x80) /* 10xxxxxx */
                return false;
        return true;
}

static inline void merge_continuation_char(uint32_t *u_ch, uint8_t ch) {
        *u_ch <<= 6;
        *u_ch |= ch & 0x3f;
}

static char* utf8_validate(const char *str, char *output) {
        uint32_t val = 0;
        uint32_t min = 0;
        const uint8_t *p, *last;
        int size;
        uint8_t *o;

        assert(str);

        o = (uint8_t*) output;
        for (p = (const uint8_t*) str; *p; p++) {
                if (*p < 128) {
                        if (o)
                                *o = *p;
                } else {
                        last = p;

                        if ((*p & 0xe0) == 0xc0) { /* 110xxxxx two-char seq. */
                                size = 2;
                                min = 128;
                                val = (uint32_t) (*p & 0x1e);
                                goto ONE_REMAINING;
                        } else if ((*p & 0xf0) == 0xe0) { /* 1110xxxx three-char seq.*/
                                size = 3;
                                min = (1 << 11);
                                val = (uint32_t) (*p & 0x0f);
                                goto TWO_REMAINING;
                        } else if ((*p & 0xf8) == 0xf0) { /* 11110xxx four-char seq */
                                size = 4;
                                min = (1 << 16);
                                val = (uint32_t) (*p & 0x07);
                        } else
                                goto error;

                        p++;
                        if (!is_continuation_char(*p))
                                goto error;
                        merge_continuation_char(&val, *p);

                TWO_REMAINING:
                        p++;
                        if (!is_continuation_char(*p))
                                goto error;
                        merge_continuation_char(&val, *p);

                ONE_REMAINING:
                        p++;
                        if (!is_continuation_char(*p))
                                goto error;
                        merge_continuation_char(&val, *p);

                        if (val < min)
                                goto error;

                        if (!is_unicode_valid(val))
                                goto error;

                        if (o) {
                                memcpy(o, last, (size_t) size);
                                o += size;
                        }

                        continue;

                error:
                        if (o) {
                                *o = FILTER_CHAR;
                                p = last; /* We retry at the next character */
                        } else
                                goto failure;
                }

                if (o)
                        o++;
        }

        if (o) {
                *o = '\0';
                return output;
        }

        return (char*) str;

failure:
        return NULL;
}

char* utf8_is_valid (const char *str) {
        return utf8_validate(str, NULL);
}

char* utf8_filter (const char *str) {
        char *new_str;

        assert(str);

        new_str = malloc(strlen(str) + 1);
        if (!new_str)
                return NULL;

        return utf8_validate(str, new_str);
}

char *ascii_is_valid(const char *str) {
        const char *p;

        assert(str);

        for (p = str; *p; p++)
                if ((unsigned char) *p >= 128)
                        return NULL;

        return (char*) str;
}

char *ascii_filter(const char *str) {
        char *r, *s, *d;
        size_t l;

        assert(str);

        l = strlen(str);
        r = malloc(l + 1);
        if (!r)
                return NULL;

        for (s = r, d = r; *s; s++)
                if ((unsigned char) *s < 128)
                        *(d++) = *s;

        *d = 0;

        return r;
}
