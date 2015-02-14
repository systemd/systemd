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
 * Terminal Parser Tests
 */

#include <stdio.h>
#include <string.h>
#include "macro.h"
#include "term-internal.h"
#include "utf8.h"

static void test_term_utf8_invalid(void) {
        term_utf8 p = { };
        uint32_t *res;
        size_t len;

        len = term_utf8_decode(NULL, NULL, 0);
        assert_se(!len);

        len = term_utf8_decode(&p, NULL, 0);
        assert_se(len == 1);

        res = NULL;
        len = term_utf8_decode(NULL, &res, 0);
        assert_se(!len);
        assert_se(res != NULL);
        assert_se(!*res);

        len = term_utf8_decode(&p, &res, 0);
        assert_se(len == 1);
        assert_se(res != NULL);
        assert_se(!*res);

        len = term_utf8_decode(&p, &res, 0xCf);
        assert_se(len == 0);
        assert_se(res != NULL);
        assert_se(!*res);

        len = term_utf8_decode(&p, &res, 0);
        assert_se(len == 2);
        assert_se(res != NULL);
        assert_se(res[0] == 0xCf && res[1] == 0);
}

static void test_term_utf8_range(void) {
        term_utf8 p = { };
        uint32_t *res;
        char u8[4];
        uint32_t i, j;
        size_t ulen, len;

        /* Convert all ucs-4 chars to utf-8 and back */

        for (i = 0; i < 0x10FFFF; ++i) {
                ulen = utf8_encode_unichar(u8, i);
                if (!ulen)
                        continue;

                for (j = 0; j < ulen; ++j) {
                        len = term_utf8_decode(&p, &res, u8[j]);
                        if (len < 1) {
                                assert_se(j + 1 != ulen);
                                continue;
                        }

                        assert_se(j + 1 == ulen);
                        assert_se(len == 1 && *res == i);
                        assert_se(i <= 127 || ulen >= 2);
                }
        }
}

static void test_term_utf8_mix(void) {
        static const char source[] = {
                0x00,                           /* normal 0 */
                0xC0, 0x80,                     /* overlong 0 */
                0xC0, 0x81,                     /* overlong 1 */
                0xE0, 0x80, 0x81,               /* overlong 1 */
                0xF0, 0x80, 0x80, 0x81,         /* overlong 1 */
                0xC0, 0x00,                     /* invalid continuation */
                0xC0, 0xC0, 0x81,               /* invalid continuation with a following overlong 1 */
                0xF8, 0x80, 0x80, 0x80, 0x81,   /* overlong 1 with 5 bytes */
                0xE0, 0x80, 0xC0, 0x81,         /* invalid 3-byte followed by valid 2-byte */
                0xF0, 0x80, 0x80, 0xC0, 0x81,   /* invalid 4-byte followed by valid 2-byte */
        };
        static const uint32_t result[] = {
                0x0000,
                0x0000,
                0x0001,
                0x0001,
                0x0001,
                0x00C0, 0x0000,
                0x00C0, 0x0001,
                0x00F8, 0x0080, 0x0080, 0x0080, 0x0081,
                0x00E0, 0x0080, 0x0001,
                0x00F0, 0x0080, 0x0080, 0x0001,
        };
        term_utf8 p = { };
        uint32_t *res;
        unsigned int i, j;
        size_t len;

        for (i = 0, j = 0; i < sizeof(source); ++i) {
                len = term_utf8_decode(&p, &res, source[i]);
                if (len < 1)
                        continue;

                assert_se(j + len <= ELEMENTSOF(result));
                assert_se(!memcmp(res, &result[j], sizeof(uint32_t) * len));
                j += len;
        }

        assert_se(j == ELEMENTSOF(result));
}

int main(int argc, char *argv[]) {
        test_term_utf8_invalid();
        test_term_utf8_range();
        test_term_utf8_mix();

        return 0;
}
