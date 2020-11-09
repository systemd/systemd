/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "def.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"
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
                assert_se(streq(t1, n));
                assert_se(streq(t2, n));
                assert_se(streq(t3, n));
        }
}

static void test_ellipsize_mem(void) {
        const char *s;
        ssize_t l, k;

        FOREACH_STRING(s,
                       "_XXXXXXXXXXX_", /* ASCII */
                       "_aąęółśćńżźć_", /* two-byte utf-8 */
                       "გამარჯობა",     /* multi-byte utf-8 */
                       "你好世界",       /* wide characters */
                       "你გą世óoó界")    /* a mix */

                for (l = strlen(s); l >= 0; l--)
                        for (k = strlen(s) + 1; k >= 0; k--)
                                test_ellipsize_mem_one(s, l, k);
}

static void test_ellipsize_one(const char *p) {
        _cleanup_free_ char *t;
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

static void test_ellipsize(void) {
        test_ellipsize_one(DIGITS LETTERS DIGITS LETTERS);
        test_ellipsize_one("한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어한국어");
        test_ellipsize_one("-日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国日本国");
        test_ellipsize_one("中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国中国-中国中国中国中国中国中国中国中国中国中国中国中国中国");
        test_ellipsize_one("sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd sÿstëmd");
        test_ellipsize_one("🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮🐮");
        test_ellipsize_one("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
        test_ellipsize_one("shórt");
}

int main(int argc, char *argv[]) {
        test_ellipsize_mem();
        test_ellipsize();

        return 0;
}
