/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "utf8.h"

TEST(utf8_is_printable) {
        assert_se(utf8_is_printable("ascii is valid\tunicode", 22));
        assert_se(utf8_is_printable("\342\204\242", 3));
        assert_se(!utf8_is_printable("\341\204", 2));
        assert_se(utf8_is_printable("ąę", 4));
        assert_se(!utf8_is_printable("\r", 1));
        assert_se(utf8_is_printable("\n", 1));
        assert_se(utf8_is_printable("\t", 1));
}

TEST(utf8_is_safe) {
        ASSERT_FALSE(utf8_is_safe("\r"));
        ASSERT_FALSE(utf8_is_safe("\n"));
        ASSERT_FALSE(utf8_is_safe("\t"));
        ASSERT_FALSE(utf8_is_safe("\x7f"));
        ASSERT_FALSE(utf8_is_safe("ascii is valid\tunicode"));
        ASSERT_TRUE(utf8_is_safe("ascii is valid unicode"));
        ASSERT_TRUE(utf8_is_safe("ąę"));
        ASSERT_TRUE(utf8_is_safe("\342\204\242"));
        ASSERT_FALSE(utf8_is_safe("\341\204"));
}

TEST(utf8_n_is_valid) {
        assert_se( utf8_is_valid_n("ascii is valid unicode", 21));
        assert_se( utf8_is_valid_n("ascii is valid unicode", 22));
        assert_se(!utf8_is_valid_n("ascii is valid unicode", 23));
        assert_se( utf8_is_valid_n("\342\204\242", 0));
        assert_se(!utf8_is_valid_n("\342\204\242", 1));
        assert_se(!utf8_is_valid_n("\342\204\242", 2));
        assert_se( utf8_is_valid_n("\342\204\242", 3));
        assert_se(!utf8_is_valid_n("\342\204\242", 4));
        assert_se( utf8_is_valid_n("<ZZ>", 0));
        assert_se( utf8_is_valid_n("<ZZ>", 1));
        assert_se( utf8_is_valid_n("<ZZ>", 2));
        assert_se( utf8_is_valid_n("<ZZ>", 3));
        assert_se( utf8_is_valid_n("<ZZ>", 4));
        assert_se(!utf8_is_valid_n("<ZZ>", 5));
}

TEST(utf8_is_valid) {
        assert_se(utf8_is_valid("ascii is valid unicode"));
        assert_se(utf8_is_valid("\342\204\242"));
        assert_se(!utf8_is_valid("\341\204"));
}

TEST(ascii_is_valid) {
        assert_se( ascii_is_valid("alsdjf\t\vbarr\nba z"));
        assert_se(!ascii_is_valid("\342\204\242"));
        assert_se(!ascii_is_valid("\341\204"));
}

TEST(ascii_is_valid_n) {
        assert_se( ascii_is_valid_n("alsdjf\t\vbarr\nba z", 17));
        assert_se( ascii_is_valid_n("alsdjf\t\vbarr\nba z", 16));
        assert_se(!ascii_is_valid_n("alsdjf\t\vbarr\nba z", 18));
        assert_se(!ascii_is_valid_n("\342\204\242", 3));
        assert_se(!ascii_is_valid_n("\342\204\242", 2));
        assert_se(!ascii_is_valid_n("\342\204\242", 1));
        assert_se( ascii_is_valid_n("\342\204\242", 0));
}

static void test_utf8_to_ascii_one(const char *s, int r_expected, const char *expected) {
        _cleanup_free_ char *ans = NULL;
        int r;

        r = utf8_to_ascii(s, '*', &ans);
        log_debug("\"%s\" → %d/\"%s\" (expected %d/\"%s\")", s, r, strnull(ans), r_expected, strnull(expected));
        assert_se(r == r_expected);
        ASSERT_STREQ(ans, expected);
}

TEST(utf8_to_ascii) {
        test_utf8_to_ascii_one("asdf", 0, "asdf");
        test_utf8_to_ascii_one("dąb", 0, "d*b");
        test_utf8_to_ascii_one("żęśłą óźń", 0, "***** ***");
        test_utf8_to_ascii_one("\342\204\242", 0, "*");
        test_utf8_to_ascii_one("\342\204", -EINVAL, NULL); /* truncated */
        test_utf8_to_ascii_one("\342", -EINVAL, NULL); /* truncated */
        test_utf8_to_ascii_one("\302\256", 0, "*");
        test_utf8_to_ascii_one("", 0, "");
        test_utf8_to_ascii_one(" ", 0, " ");
        test_utf8_to_ascii_one("\t", 0, "\t");
        test_utf8_to_ascii_one("串", 0, "*");
        test_utf8_to_ascii_one("…👊🔪💐…", 0, "*****");
}

TEST(utf8_encoded_valid_unichar) {
        assert_se(utf8_encoded_valid_unichar("\342\204\242", 1) == -EINVAL); /* truncated */
        assert_se(utf8_encoded_valid_unichar("\342\204\242", 2) == -EINVAL); /* truncated */
        assert_se(utf8_encoded_valid_unichar("\342\204\242", 3) == 3);
        assert_se(utf8_encoded_valid_unichar("\342\204\242", 4) == 3);
        assert_se(utf8_encoded_valid_unichar("\302\256", 1) == -EINVAL); /* truncated */
        assert_se(utf8_encoded_valid_unichar("\302\256", 2) == 2);
        assert_se(utf8_encoded_valid_unichar("\302\256", 3) == 2);
        assert_se(utf8_encoded_valid_unichar("\302\256", SIZE_MAX) == 2);
        assert_se(utf8_encoded_valid_unichar("a", 1) == 1);
        assert_se(utf8_encoded_valid_unichar("a", 2) == 1);
        assert_se(utf8_encoded_valid_unichar("\341\204", 1) == -EINVAL); /* truncated, potentially valid */
        assert_se(utf8_encoded_valid_unichar("\341\204", 2) == -EINVAL); /* truncated, potentially valid */
        assert_se(utf8_encoded_valid_unichar("\341\204", 3) == -EINVAL);
        assert_se(utf8_encoded_valid_unichar("\341\204\341\204", 4) == -EINVAL);
        assert_se(utf8_encoded_valid_unichar("\341\204\341\204", 5) == -EINVAL);
}

TEST(utf8_escape_invalid) {
        _cleanup_free_ char *p1 = NULL, *p2 = NULL, *p3 = NULL;

        p1 = utf8_escape_invalid("goo goo goo");
        log_debug("\"%s\"", p1);
        assert_se(utf8_is_valid(p1));

        p2 = utf8_escape_invalid("\341\204\341\204");
        log_debug("\"%s\"", p2);
        assert_se(utf8_is_valid(p2));

        p3 = utf8_escape_invalid("\341\204");
        log_debug("\"%s\"", p3);
        assert_se(utf8_is_valid(p3));
}

TEST(utf8_escape_non_printable) {
        _cleanup_free_ char *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL, *p5 = NULL, *p6 = NULL;

        p1 = utf8_escape_non_printable("goo goo goo");
        log_debug("\"%s\"", p1);
        assert_se(utf8_is_valid(p1));

        p2 = utf8_escape_non_printable("\341\204\341\204");
        log_debug("\"%s\"", p2);
        assert_se(utf8_is_valid(p2));

        p3 = utf8_escape_non_printable("\341\204");
        log_debug("\"%s\"", p3);
        assert_se(utf8_is_valid(p3));

        p4 = utf8_escape_non_printable("ąę\n가너도루\n1234\n\341\204\341\204\n\001 \019\20\a");
        log_debug("\"%s\"", p4);
        assert_se(utf8_is_valid(p4));

        p5 = utf8_escape_non_printable("\001 \019\20\a");
        log_debug("\"%s\"", p5);
        assert_se(utf8_is_valid(p5));

        p6 = utf8_escape_non_printable("\xef\xbf\x30\x13");
        log_debug("\"%s\"", p6);
        assert_se(utf8_is_valid(p6));
}

TEST(utf8_escape_non_printable_full) {
        FOREACH_STRING(s,
                       "goo goo goo",       /* ASCII */
                       "\001 \019\20\a",    /* control characters */
                       "\xef\xbf\x30\x13")  /* misplaced continuation bytes followed by a digit and cc */
                for (size_t cw = 0; cw < 22; cw++) {
                        _cleanup_free_ char *p = NULL, *q = NULL;
                        size_t ew;

                        p = utf8_escape_non_printable_full(s, cw, false);
                        ew = utf8_console_width(p);
                        log_debug("%02zu \"%s\" (%zu wasted)", cw, p, cw - ew);
                        assert_se(utf8_is_valid(p));
                        assert_se(ew <= cw);

                        q = utf8_escape_non_printable_full(s, cw, true);
                        ew = utf8_console_width(q);
                        log_debug("   \"%s\" (%zu wasted)", q, cw - ew);
                        assert_se(utf8_is_valid(q));
                        assert_se(ew <= cw);
                        if (cw > 0)
                                assert_se(endswith(q, "…"));
                }
}

TEST(utf16_to_utf8) {
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
        a = utf16_to_utf8(b, SIZE_MAX);
        assert_se(a);
        assert_se(strlen(a) == sizeof(utf8));
        assert_se(memcmp(a, utf8, sizeof(utf8)) == 0);
}

TEST(utf8_n_codepoints) {
        assert_se(utf8_n_codepoints("abc") == 3);
        assert_se(utf8_n_codepoints("zażółcić gęślą jaźń") == 19);
        assert_se(utf8_n_codepoints("串") == 1);
        assert_se(utf8_n_codepoints("") == 0);
        assert_se(utf8_n_codepoints("…👊🔪💐…") == 5);
        assert_se(utf8_n_codepoints("\xF1") == SIZE_MAX);
}

TEST(utf8_console_width) {
        assert_se(utf8_console_width("abc") == 3);
        assert_se(utf8_console_width("zażółcić gęślą jaźń") == 19);
        assert_se(utf8_console_width("串") == 2);
        assert_se(utf8_console_width("") == 0);
        assert_se(utf8_console_width("…👊🔪💐…") == 8);
        assert_se(utf8_console_width("\xF1") == SIZE_MAX);
}

TEST(utf8_to_utf16) {
        FOREACH_STRING(p,
                       "abc",
                       "zażółcić gęślą jaźń",
                       "串",
                       "",
                       "…👊🔪💐…") {

                _cleanup_free_ char16_t *a = NULL;
                _cleanup_free_ char *b = NULL;

                a = utf8_to_utf16(p, SIZE_MAX);
                assert_se(a);

                b = utf16_to_utf8(a, SIZE_MAX);
                assert_se(b);
                ASSERT_STREQ(p, b);
        }
}

TEST(utf8_last_length) {
        ASSERT_EQ(utf8_last_length("", 0), 0U);
        ASSERT_EQ(utf8_last_length("", SIZE_MAX), 0U);
        ASSERT_EQ(utf8_last_length("a", 1), 1U);
        ASSERT_EQ(utf8_last_length("a", SIZE_MAX), 1U);
        ASSERT_EQ(utf8_last_length("ä", SIZE_MAX), strlen("ä"));
        ASSERT_EQ(utf8_last_length("👊", SIZE_MAX), strlen("👊"));
        ASSERT_EQ(utf8_last_length("koffa", SIZE_MAX), 1U);
        ASSERT_EQ(utf8_last_length("koffä", SIZE_MAX), strlen("ä"));
        ASSERT_EQ(utf8_last_length("koff👊", SIZE_MAX), strlen("👊"));
}

DEFINE_TEST_MAIN(LOG_INFO);
