/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "string-util.h"
#include "strv.h"
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
        assert_se( ascii_is_valid("alsdjf\t\vbarr\nba z"));
        assert_se(!ascii_is_valid("\342\204\242"));
        assert_se(!ascii_is_valid("\341\204"));
}

static void test_ascii_is_valid_n(void) {
        assert_se( ascii_is_valid_n("alsdjf\t\vbarr\nba z", 17));
        assert_se( ascii_is_valid_n("alsdjf\t\vbarr\nba z", 16));
        assert_se(!ascii_is_valid_n("alsdjf\t\vbarr\nba z", 18));
        assert_se(!ascii_is_valid_n("\342\204\242", 3));
        assert_se(!ascii_is_valid_n("\342\204\242", 2));
        assert_se(!ascii_is_valid_n("\342\204\242", 1));
        assert_se( ascii_is_valid_n("\342\204\242", 0));
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
        const char16_t utf16[] = { htole16('a'), htole16(0xd800), htole16('b'), htole16(0xdc00), htole16('c'), htole16(0xd801), htole16(0xdc37) };
        static const char utf8[] = { 'a', 'b', 'c', 0xf0, 0x90, 0x90, 0xb7 };
        _cleanup_free_ char16_t *b = NULL;
        _cleanup_free_ char *a = NULL;

        /* Convert UTF-16 to UTF-8, filtering embedded bad chars */
        a = utf16_to_utf8(utf16, sizeof(utf16));
        assert_se(a);
        assert_se(memcmp(a, utf8, sizeof(utf8)) == 0);

        /* Convert UTF-8 to UTF-16, and back */
        b = utf8_to_utf16(utf8, sizeof(utf8));
        assert_se(b);

        free(a);
        a = utf16_to_utf8(b, char16_strlen(b) * 2);
        assert_se(a);
        assert_se(strlen(a) == sizeof(utf8));
        assert_se(memcmp(a, utf8, sizeof(utf8)) == 0);
}

static void test_utf8_n_codepoints(void) {
        assert_se(utf8_n_codepoints("abc") == 3);
        assert_se(utf8_n_codepoints("zażółcić gęślą jaźń") == 19);
        assert_se(utf8_n_codepoints("串") == 1);
        assert_se(utf8_n_codepoints("") == 0);
        assert_se(utf8_n_codepoints("…👊🔪💐…") == 5);
        assert_se(utf8_n_codepoints("\xF1") == (size_t) -1);
}

static void test_utf8_console_width(void) {
        assert_se(utf8_console_width("abc") == 3);
        assert_se(utf8_console_width("zażółcić gęślą jaźń") == 19);
        assert_se(utf8_console_width("串") == 2);
        assert_se(utf8_console_width("") == 0);
        assert_se(utf8_console_width("…👊🔪💐…") == 8);
        assert_se(utf8_console_width("\xF1") == (size_t) -1);
}

static void test_utf8_to_utf16(void) {
        const char *p;

        FOREACH_STRING(p,
                       "abc",
                       "zażółcić gęślą jaźń",
                       "串",
                       "",
                       "…👊🔪💐…") {

                _cleanup_free_ char16_t *a = NULL;
                _cleanup_free_ char *b = NULL;

                a = utf8_to_utf16(p, strlen(p));
                assert_se(a);

                b = utf16_to_utf8(a, char16_strlen(a) * 2);
                assert_se(b);
                assert_se(streq(p, b));
        }
}

int main(int argc, char *argv[]) {
        test_utf8_is_valid();
        test_utf8_is_printable();
        test_ascii_is_valid();
        test_ascii_is_valid_n();
        test_utf8_encoded_valid_unichar();
        test_utf8_escaping();
        test_utf8_escaping_printable();
        test_utf16_to_utf8();
        test_utf8_n_codepoints();
        test_utf8_console_width();
        test_utf8_to_utf16();

        return 0;
}
