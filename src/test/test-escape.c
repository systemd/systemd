/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "macro.h"
#include "tests.h"

TEST(cescape) {
        _cleanup_free_ char *t = NULL;

        assert_se(t = cescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313"));
        ASSERT_STREQ(t, "abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\a\\003\\177\\234\\313");
}

TEST(xescape) {
        _cleanup_free_ char *t = NULL;

        assert_se(t = xescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313", /* bad= */ NULL));
        ASSERT_STREQ(t, "abc\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\\x7f\\x9c\\xcb");
}

static void test_xescape_full_one(bool eight_bits) {
        const char* escaped = !eight_bits ?
                "a\\x62c\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\\x7f\\x9c\\xcb" :
                "a\\x62c\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\177\234\313";
        const unsigned full_fit = !eight_bits ? 55 : 46;
        XEscapeFlags flags = eight_bits * XESCAPE_8_BIT;

        log_info("/* %s */", __func__);

        for (unsigned i = 0; i < 60; i++) {
                _cleanup_free_ char *t = NULL, *q = NULL;

                assert_se(t = xescape_full("abc\\\"\b\f\n\r\t\v\a\003\177\234\313", "b", i, flags));

                log_info("%02u: <%s>", i, t);

                if (i >= full_fit)
                        ASSERT_STREQ(t, escaped);
                else if (i >= 3) {
                        /* We need up to four columns, so up to three columns may be wasted */
                        assert_se(strlen(t) == i || strlen(t) == i - 1 || strlen(t) == i - 2 || strlen(t) == i - 3);
                        assert_se(strneq(t, escaped, i - 3) || strneq(t, escaped, i - 4) ||
                                  strneq(t, escaped, i - 5) || strneq(t, escaped, i - 6));
                        assert_se(endswith(t, "..."));
                } else {
                        assert_se(strlen(t) == i);
                        assert_se(strneq(t, "...", i));
                }

                assert_se(q = xescape_full("abc\\\"\b\f\n\r\t\v\a\003\177\234\313", "b", i,
                                           flags | XESCAPE_FORCE_ELLIPSIS));

                log_info("%02u: <%s>", i, q);
                if (i > 0)
                        assert_se(endswith(q, "."));
                assert_se(strlen(q) <= i);
                assert_se(strlen(q) + 3 >= strlen(t));
        }
}

TEST(xescape_full) {
        test_xescape_full_one(false);
        test_xescape_full_one(true);
}

TEST(cunescape) {
        _cleanup_free_ char *unescaped = NULL;

        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", 0, &unescaped) < 0);
        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "abc\\\"\b\f\a\n\r\t\v\003\177\234\313\\000\\x00");
        unescaped = mfree(unescaped);

        /* incomplete sequences */
        assert_se(cunescape("\\x0", 0, &unescaped) < 0);
        assert_se(cunescape("\\x0", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "\\x0");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\x", 0, &unescaped) < 0);
        assert_se(cunescape("\\x", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "\\x");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\", 0, &unescaped) < 0);
        assert_se(cunescape("\\", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "\\");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\11", 0, &unescaped) < 0);
        assert_se(cunescape("\\11", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "\\11");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\1", 0, &unescaped) < 0);
        assert_se(cunescape("\\1", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "\\1");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\u0000", 0, &unescaped) < 0);
        assert_se(cunescape("\\u00DF\\U000000df\\u03a0\\U00000041", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "ßßΠA");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\073", 0, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, ";");
        unescaped = mfree(unescaped);

        assert_se(cunescape("A=A\\\\x0aB", 0, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "A=A\\x0aB");
        unescaped = mfree(unescaped);

        assert_se(cunescape("A=A\\\\x0aB", UNESCAPE_RELAX, &unescaped) >= 0);
        ASSERT_STREQ(unescaped, "A=A\\x0aB");
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\x00\\x00\\x00", UNESCAPE_ACCEPT_NUL, &unescaped) == 3);
        assert_se(memcmp(unescaped, "\0\0\0", 3) == 0);
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\u0000\\u0000\\u0000", UNESCAPE_ACCEPT_NUL, &unescaped) == 3);
        assert_se(memcmp(unescaped, "\0\0\0", 3) == 0);
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\U00000000\\U00000000\\U00000000", UNESCAPE_ACCEPT_NUL, &unescaped) == 3);
        assert_se(memcmp(unescaped, "\0\0\0", 3) == 0);
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\000\\000\\000", UNESCAPE_ACCEPT_NUL, &unescaped) == 3);
        assert_se(memcmp(unescaped, "\0\0\0", 3) == 0);
}

static void test_shell_escape_one(const char *s, const char *bad, const char *expected) {
        _cleanup_free_ char *r = NULL;

        assert_se(r = shell_escape(s, bad));
        log_debug("%s → %s (expected %s)", s, r, expected);
        ASSERT_STREQ(r, expected);
}

TEST(shell_escape) {
        test_shell_escape_one("", "", "");
        test_shell_escape_one("\\", "", "\\\\");
        test_shell_escape_one("foobar", "", "foobar");
        test_shell_escape_one("foobar", "o", "f\\o\\obar");
        test_shell_escape_one("foo:bar,baz", ",:", "foo\\:bar\\,baz");
        test_shell_escape_one("foo\nbar\nbaz", ",:", "foo\\nbar\\nbaz");
}

static void test_shell_maybe_quote_one(const char *s, ShellEscapeFlags flags, const char *expected) {
        _cleanup_free_ char *ret = NULL;

        assert_se(ret = shell_maybe_quote(s, flags));
        log_debug("[%s] → [%s] (%s)", s, ret, expected);
        ASSERT_STREQ(ret, expected);
}

TEST(shell_maybe_quote) {
        test_shell_maybe_quote_one("", 0, "");
        test_shell_maybe_quote_one("", SHELL_ESCAPE_EMPTY, "\"\"");
        test_shell_maybe_quote_one("", SHELL_ESCAPE_POSIX, "");
        test_shell_maybe_quote_one("", SHELL_ESCAPE_POSIX | SHELL_ESCAPE_EMPTY, "\"\"");
        test_shell_maybe_quote_one("\\", 0, "\"\\\\\"");
        test_shell_maybe_quote_one("\\", SHELL_ESCAPE_POSIX, "$'\\\\'");
        test_shell_maybe_quote_one("\"", 0, "\"\\\"\"");
        test_shell_maybe_quote_one("\"", SHELL_ESCAPE_POSIX, "$'\"'");
        test_shell_maybe_quote_one("foobar", 0, "foobar");
        test_shell_maybe_quote_one("foobar", SHELL_ESCAPE_POSIX, "foobar");
        test_shell_maybe_quote_one("foo bar", 0, "\"foo bar\"");
        test_shell_maybe_quote_one("foo bar", SHELL_ESCAPE_POSIX, "$'foo bar'");
        test_shell_maybe_quote_one("foo\tbar", 0, "\"foo\\tbar\"");
        test_shell_maybe_quote_one("foo\tbar", SHELL_ESCAPE_POSIX, "$'foo\\tbar'");
        test_shell_maybe_quote_one("foo\nbar", 0, "\"foo\\nbar\"");
        test_shell_maybe_quote_one("foo\nbar", SHELL_ESCAPE_POSIX, "$'foo\\nbar'");
        test_shell_maybe_quote_one("foo \"bar\" waldo", 0, "\"foo \\\"bar\\\" waldo\"");
        test_shell_maybe_quote_one("foo \"bar\" waldo", SHELL_ESCAPE_POSIX, "$'foo \"bar\" waldo'");
        test_shell_maybe_quote_one("foo$bar", 0, "\"foo\\$bar\"");
        test_shell_maybe_quote_one("foo$bar", SHELL_ESCAPE_EMPTY, "\"foo\\$bar\"");
        test_shell_maybe_quote_one("foo$bar", SHELL_ESCAPE_POSIX, "$'foo$bar'");
        test_shell_maybe_quote_one("foo$bar", SHELL_ESCAPE_POSIX | SHELL_ESCAPE_EMPTY, "$'foo$bar'");

        /* Exclamation mark is special in the interactive shell, but we don't treat it so. */
        test_shell_maybe_quote_one("foo!bar", 0, "\"foo!bar\"");
        test_shell_maybe_quote_one("foo!bar", SHELL_ESCAPE_POSIX, "$'foo!bar'");

        /* Control characters and unicode */
        test_shell_maybe_quote_one("a\nb\001", 0, "\"a\\nb\\001\"");
        test_shell_maybe_quote_one("a\nb\001", SHELL_ESCAPE_POSIX, "$'a\\nb\\001'");

        test_shell_maybe_quote_one("głąb", 0, "głąb");
        test_shell_maybe_quote_one("głąb", SHELL_ESCAPE_POSIX, "głąb");

        test_shell_maybe_quote_one("głąb\002\003", 0, "\"głąb\\002\\003\"");
        test_shell_maybe_quote_one("głąb\002\003", SHELL_ESCAPE_POSIX, "$'głąb\\002\\003'");

        test_shell_maybe_quote_one("głąb\002\003rząd", 0, "\"głąb\\002\\003rząd\"");
        test_shell_maybe_quote_one("głąb\002\003rząd", SHELL_ESCAPE_POSIX, "$'głąb\\002\\003rząd'");

        /* Bogus UTF-8 strings */
        test_shell_maybe_quote_one("\250\350", 0, "\"\\250\\350\"");
        test_shell_maybe_quote_one("\250\350", SHELL_ESCAPE_POSIX, "$'\\250\\350'");
}

static void test_quote_command_line_one(char **argv, const char *expected) {
        _cleanup_free_ char *s = NULL;

        assert_se(s = quote_command_line(argv, SHELL_ESCAPE_EMPTY));
        log_info("%s", s);
        ASSERT_STREQ(s, expected);
}

TEST(quote_command_line) {
        test_quote_command_line_one(STRV_MAKE("true", "true"),
                                    "true true");
        test_quote_command_line_one(STRV_MAKE("true", "with a space"),
                                    "true \"with a space\"");
        test_quote_command_line_one(STRV_MAKE("true", "with a 'quote'"),
                                    "true \"with a 'quote'\"");
        test_quote_command_line_one(STRV_MAKE("true", "with a \"quote\""),
                                    "true \"with a \\\"quote\\\"\"");
        test_quote_command_line_one(STRV_MAKE("true", "$dollar"),
                                    "true \"\\$dollar\"");
}

static void test_octescape_one(const char *s, const char *expected) {
        _cleanup_free_ char *ret = NULL;

        assert_se(ret = octescape(s, strlen_ptr(s)));
        log_debug("octescape(\"%s\") → \"%s\" (expected: \"%s\")", strnull(s), ret, expected);
        ASSERT_STREQ(ret, expected);
}

TEST(octescape) {
        test_octescape_one(NULL, "");
        test_octescape_one("", "");
        test_octescape_one("foo", "foo");
        test_octescape_one("\"\\\"", "\\042\\134\\042");
        test_octescape_one("\123\213\222", "\123\\213\\222");
}

static void test_decescape_one(const char *s, const char *bad, const char *expected) {
        _cleanup_free_ char *ret = NULL;

        assert_se(ret = decescape(s, bad, strlen_ptr(s)));
        log_debug("decescape(\"%s\") → \"%s\" (expected: \"%s\")", strnull(s), ret, expected);
        ASSERT_STREQ(ret, expected);
}

TEST(decescape) {
        test_decescape_one(NULL, "bad", "");
        test_decescape_one("foo", "", "foo");
        test_decescape_one("foo", "f", "\\102oo");
        test_decescape_one("foo", "o", "f\\111\\111");
        test_decescape_one("go\"bb\\ledyg\x03ook\r\n", "", "go\\034bb\\092ledyg\\003ook\\013\\010");
        test_decescape_one("\\xff\xff" "f", "f", "\\092x\\102\\102\\255\\102");
        test_decescape_one("all", "all", "\\097\\108\\108");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
