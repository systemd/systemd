/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "escape.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "utf8.h"

static void test_ellipsize_mem_one(const char *s, size_t old_length, size_t new_length) {
        _cleanup_free_ char *n = NULL;
        _cleanup_free_ char *t1 = NULL, *t2 = NULL, *t3 = NULL;
        char buf[LINE_MAX];
        bool has_wide_chars;
        size_t max_width;

        n = memdup_suffix0(s, old_length);

        if (!utf8_is_valid(n))
                /* We don't support invalid sequences… */
                return;

        /* Report out inputs. We duplicate the data so that cellescape
         * can properly report truncated multibyte sequences. */
        log_info("%s \"%s\" old_length=%zu/%zu new_length=%zu", __func__,
                 cellescape(buf, sizeof buf, n),
                 old_length, utf8_console_width(n),
                 new_length);

        /* To keep this test simple, any case with wide chars starts with this glyph */
        has_wide_chars = startswith(s, "你");
        max_width = MIN(utf8_console_width(n), new_length);

        t1 = ellipsize_mem(n, old_length, new_length, 30);
        log_info("30%% → %s utf8_console_width=%zu", t1, utf8_console_width(t1));
        if (!has_wide_chars)
                assert_se(utf8_console_width(t1) == max_width);
        else
                assert_se(utf8_console_width(t1) <= max_width);

        t2 = ellipsize_mem(n, old_length, new_length, 90);
        log_info("90%% → %s utf8_console_width=%zu", t2, utf8_console_width(t2));
        if (!has_wide_chars)
                assert_se(utf8_console_width(t2) == max_width);
        else
                assert_se(utf8_console_width(t2) <= max_width);

        t3 = ellipsize_mem(n, old_length, new_length, 100);
        log_info("100%% → %s utf8_console_width=%zu", t3, utf8_console_width(t3));
        if (!has_wide_chars)
                assert_se(utf8_console_width(t3) == max_width);
        else
                assert_se(utf8_console_width(t3) <= max_width);

        if (new_length >= old_length) {
                ASSERT_STREQ(t1, n);
                ASSERT_STREQ(t2, n);
                ASSERT_STREQ(t3, n);
        }
}

TEST(ellipsize_mem) {
        FOREACH_STRING(s,
                       "_XXXXXXXXXXX_", /* ASCII */
                       "_aąęółśćńżźć_", /* two-byte utf-8 */
                       "გამარჯობა",     /* multi-byte utf-8 */
                       "你好世界",       /* wide characters */
                       "你გą世óoó界")    /* a mix */
                for (ssize_t l = strlen(s); l >= 0; l--)
                        for (ssize_t k = strlen(s) + 1; k >= 0; k--)
                                test_ellipsize_mem_one(s, l, k);
}

TEST(ellipsize_mem_truncated_utf8) {
        static const char s[] = { 'a', '\xf0', '\x80', '\x80', '\x80', 'b' };

        ASSERT_NULL(ellipsize_mem(s, 2, 1, 50));
}

static void test_ellipsize_one(const char *p) {
        _cleanup_free_ char *t = NULL;
        t = ellipsize(p, columns(), 70);
        puts(t);
        free(t);
        t = ellipsize(p, columns(), 0);
        puts(t);
        free(t);
        t = ellipsize(p, columns(), 100);
        puts(t);
        free(t);
        t = ellipsize(p, 0, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 1, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 2, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 3, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 4, 50);
        puts(t);
        free(t);
        t = ellipsize(p, 5, 50);
        puts(t);
}

TEST(ellipsize) {
        test_ellipsize_one(DIGITS LETTERS DIGITS LETTERS);
        test_ellipsize_one("한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어");
        test_ellipsize_one("-日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国");
        test_ellipsize_one("中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国-中国中国中国中国中国中国中国中国中国中国中国中国中国");
        test_ellipsize_one("sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd");
        test_ellipsize_one("🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮");
        test_ellipsize_one("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
        test_ellipsize_one("shórt");
}

TEST(ellipsize_ansi) {
        const char *s = ANSI_HIGHLIGHT_YELLOW_UNDERLINE "yęllow"
                        ANSI_HIGHLIGHT_GREY_UNDERLINE "grěy"
                        ANSI_HIGHLIGHT_BLUE_UNDERLINE "blue"
                        ANSI_NORMAL "nórmął";
        size_t len = strlen(s);

        for (unsigned percent = 0; percent <= 100; percent += 15)
                for (ssize_t x = 21; x >= 0; x--) {
                        _cleanup_free_ char *t = ellipsize_mem(s, len, x, percent);
                        printf("%02zd: \"%s\"\n", x, t);
                        assert_se(utf8_is_valid(t));

                        if (DEBUG_LOGGING) {
                                _cleanup_free_ char *e = cescape(t);
                                printf("  : \"%s\"\n", e);
                        }
                }
}

TEST(ellipsize_ansi_cats) {
        _cleanup_free_ char *e = NULL, *f = NULL, *g = NULL, *h = NULL;

        /* Make sure we don't cut off in the middle of an ANSI escape sequence. */

        e = ellipsize("01" ANSI_NORMAL "23", 4, 0);
        puts(e);
        ASSERT_STREQ(e, "01" ANSI_NORMAL "23");
        f = ellipsize("ab" ANSI_NORMAL "cd", 4, 90);
        puts(f);
        ASSERT_STREQ(f, "ab" ANSI_NORMAL "cd");

        g = ellipsize("🐱🐱" ANSI_NORMAL "🐱🐱" ANSI_NORMAL, 5, 0);
        puts(g);
        ASSERT_STREQ(g, "…" ANSI_NORMAL "🐱🐱" ANSI_NORMAL);
        h = ellipsize("🐱🐱" ANSI_NORMAL "🐱🐱" ANSI_NORMAL, 5, 90);
        puts(h);
        ASSERT_STREQ(h, "🐱…" ANSI_NORMAL "🐱" ANSI_NORMAL);
}

TEST(ellipsize_esc_infinite_loop) {
        /* Make sure we don't infinite loop on an ESC in the first half */
        static const char s[] = { 'A', 'B', 0x1B, ' ', 'D', '\0' };
        _cleanup_free_ char *t = NULL;

        t = ellipsize_mem(s, 5, 5, 50);
        assert_se(t);
        assert_se(memcmp(t, s, 5) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
