/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Dave Reisner

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

#include "utf8.h"
#include "util.h"

static void test_utf8_is_printable(void) {
        assert_se(utf8_is_printable("ascii is valid\tunicode", 22));
        assert_se(utf8_is_printable("\342\204\242", 3));
        assert_se(!utf8_is_printable("\341\204", 2));
        assert_se(utf8_is_printable("ąę", 4));
}

static void test_utf8_is_valid(void) {
        assert_se(utf8_is_valid("ascii is valid unicode"));
        assert_se(utf8_is_valid("\342\204\242"));
        assert_se(!utf8_is_valid("\341\204"));
}

static void test_ascii_is_valid(void) {
        assert_se(ascii_is_valid("alsdjf\t\vbarr\nba z"));
        assert_se(!ascii_is_valid("\342\204\242"));
        assert_se(!ascii_is_valid("\341\204"));
}

static void test_utf8_encoded_valid_unichar(void) {
        assert_se(utf8_encoded_valid_unichar("\342\204\242") == 3);
        assert_se(utf8_encoded_valid_unichar("\302\256") == 2);
        assert_se(utf8_encoded_valid_unichar("a") == 1);
        assert_se(utf8_encoded_valid_unichar("\341\204") < 0);
        assert_se(utf8_encoded_valid_unichar("\341\204\341\204") < 0);
}

static void test_utf8_escaping(void) {
        _cleanup_free_ char *p1, *p2, *p3;

        p1 = utf8_escape_invalid("goo goo goo");
        puts(p1);
        assert_se(utf8_is_valid(p1));

        p2 = utf8_escape_invalid("\341\204\341\204");
        puts(p2);
        assert_se(utf8_is_valid(p2));

        p3 = utf8_escape_invalid("\341\204");
        puts(p3);
        assert_se(utf8_is_valid(p3));
}

static void test_utf8_escaping_printable(void) {
        _cleanup_free_ char *p1, *p2, *p3, *p4, *p5, *p6;

        p1 = utf8_escape_non_printable("goo goo goo");
        puts(p1);
        assert_se(utf8_is_valid(p1));

        p2 = utf8_escape_non_printable("\341\204\341\204");
        puts(p2);
        assert_se(utf8_is_valid(p2));

        p3 = utf8_escape_non_printable("\341\204");
        puts(p3);
        assert_se(utf8_is_valid(p3));

        p4 = utf8_escape_non_printable("ąę\n가너도루\n1234\n\341\204\341\204\n\001 \019\20\a");
        puts(p4);
        assert_se(utf8_is_valid(p4));

        p5 = utf8_escape_non_printable("\001 \019\20\a");
        puts(p5);
        assert_se(utf8_is_valid(p5));

        p6 = utf8_escape_non_printable("\xef\xbf\x30\x13");
        puts(p6);
        assert_se(utf8_is_valid(p6));
}

static void test_utf16_to_utf8(void) {
        char *a = NULL;
        const uint16_t utf16[] = { htole16('a'), htole16(0xd800), htole16('b'), htole16(0xdc00), htole16('c'), htole16(0xd801), htole16(0xdc37) };
        const char utf8[] = { 'a', 'b', 'c', 0xf0, 0x90, 0x90, 0xb7, 0 };

        a = utf16_to_utf8(utf16, 14);
        assert_se(a);
        assert_se(streq(a, utf8));

        free(a);
}

static void test_utf8_to_utf16(void) {
        char *a = NULL;
        int out_len;
        const uint16_t utf16[] = { htole16('a'), htole16('b'), htole16(0x1234), htole16(0) };
        const char utf8[] = { 'a', 'b', 0xe1, 0x88, 0xb4, 0x00 };

        /* test the U+010437 symbol */
        const uint16_t utf16_smp[] = { htole16(0xd801), htole16(0xdc37), htole16(0) };
        const char utf8_smp[] = { 0xf0, 0x90, 0x90, 0xb7, 0x00 };

        /* invalid unicode character: U+0d800 */
        const char utf8_invalid[] = { 0xf0, 0x90, 0x80, 0x80, 0x00 };

        a = utf8_to_utf16(utf8, &out_len);
        assert_se(out_len == ELEMENTSOF(utf16)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)utf16, out_len));

        free(a);

        a = utf8_to_utf16_len(utf8, &out_len, ELEMENTSOF(utf8));
        assert_se(out_len == ELEMENTSOF(utf16)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)utf16, out_len));

        free(a);

        /* utf8 too short */
        a = utf8_to_utf16_len(utf8, &out_len, 3);
        assert_se(a == NULL);

        a = utf8_to_utf16(utf8_smp, &out_len);
        assert_se(out_len == ELEMENTSOF(utf16_smp)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)utf16_smp, out_len));

        free(a);

        a = utf8_to_utf16_len(utf8_smp, &out_len, ELEMENTSOF(utf8_smp));
        assert_se(out_len = ELEMENTSOF(utf16_smp)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)utf16_smp, out_len));

        free(a);

        /* utf8 too short */
        a = utf8_to_utf16_len(utf8_smp, &out_len, 3);
        assert_se(a == NULL);

        /* invalid unicode character*/
        a = utf8_to_utf16_len(utf8_invalid, &out_len, 3);
        assert_se(a == NULL);

}

static void test_utf8_to_ucs2(void) {
        char *a = NULL;
        int out_len;
        const uint16_t ucs2[] = { htole16('a'), htole16('b'), htole16(0x1234), htole16(0) };
        const char utf8[] = { 'a', 'b', 0xe1, 0x88, 0xb4, 0x00 };

        /* test the U+010437 symbol: valid unicode, invalid ucs2 */
        const char utf8_smp[] = { 0xf0, 0x90, 0x90, 0xb7, 0x00 };

        /* invalid unicode character: U+0d800 */
        const char utf8_invalid[] = { 0xf0, 0x90, 0x80, 0x80, 0x00 };

        a = utf8_to_ucs2(utf8, &out_len);
        assert_se(out_len == ELEMENTSOF(ucs2)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)ucs2, out_len));

        free(a);

        a = utf8_to_ucs2_len(utf8, &out_len, ELEMENTSOF(utf8));
        assert_se(out_len == ELEMENTSOF(ucs2)*2);
        assert_se(a);
        assert_se(!memcmp(a, (char*)ucs2, out_len));

        free(a);

        /* utf8 too short */
        a = utf8_to_ucs2_len(utf8, &out_len, 3);
        assert_se(a == NULL);

        /* ucs2 are only BMP planes */
        a = utf8_to_ucs2(utf8_smp, &out_len);
        assert_se(a == NULL);

        /* invalid unicode character*/
        a = utf8_to_ucs2_len(utf8_invalid, &out_len, 3);
        assert_se(a == NULL);

}

int main(int argc, char *argv[]) {
        test_utf8_is_valid();
        test_utf8_is_printable();
        test_ascii_is_valid();
        test_utf8_encoded_valid_unichar();
        test_utf8_escaping();
        test_utf8_escaping_printable();
        test_utf16_to_utf8();
        test_utf8_to_utf16();
        test_utf8_to_ucs2();

        return 0;
}
