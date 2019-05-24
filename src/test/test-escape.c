/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "escape.h"
#include "macro.h"
#include "tests.h"

static void test_cescape(void) {
        _cleanup_free_ char *t;

        assert_se(t = cescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313"));
        assert_se(streq(t, "abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\a\\003\\177\\234\\313"));
}

static void test_xescape(void) {
        _cleanup_free_ char *t;

        assert_se(t = xescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313", ""));
        assert_se(streq(t, "abc\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\\x7f\\x9c\\xcb"));
}

static void test_xescape_full(bool eight_bits) {
        const char* escaped = !eight_bits ?
                "a\\x62c\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\\x7f\\x9c\\xcb" :
                "a\\x62c\\x5c\"\\x08\\x0c\\x0a\\x0d\\x09\\x0b\\x07\\x03\177\234\313";
        const unsigned full_fit = !eight_bits ? 55 : 46;

        for (unsigned i = 0; i < 60; i++) {
                _cleanup_free_ char *t;

                assert_se(t = xescape_full("abc\\\"\b\f\n\r\t\v\a\003\177\234\313", "b", i, eight_bits));

                log_info("%02d: %s", i, t);

                if (i >= full_fit)
                        assert_se(streq(t, escaped));
                else if (i >= 3) {
                        /* We need up to four columns, so up to three three columns may be wasted */
                        assert_se(strlen(t) == i || strlen(t) == i - 1 || strlen(t) == i - 2 || strlen(t) == i - 3);
                        assert_se(strneq(t, escaped, i - 3) || strneq(t, escaped, i - 4) ||
                                  strneq(t, escaped, i - 5) || strneq(t, escaped, i - 6));
                        assert_se(endswith(t, "..."));
                } else {
                        assert_se(strlen(t) == i);
                        assert_se(strneq(t, "...", i));
                }
        }
}

static void test_cunescape(void) {
        _cleanup_free_ char *unescaped;

        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", 0, &unescaped) < 0);
        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "abc\\\"\b\f\a\n\r\t\v\003\177\234\313\\000\\x00"));
        unescaped = mfree(unescaped);

        /* incomplete sequences */
        assert_se(cunescape("\\x0", 0, &unescaped) < 0);
        assert_se(cunescape("\\x0", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\x0"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\x", 0, &unescaped) < 0);
        assert_se(cunescape("\\x", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\x"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\", 0, &unescaped) < 0);
        assert_se(cunescape("\\", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\11", 0, &unescaped) < 0);
        assert_se(cunescape("\\11", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\11"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\1", 0, &unescaped) < 0);
        assert_se(cunescape("\\1", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\1"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\u0000", 0, &unescaped) < 0);
        assert_se(cunescape("\\u00DF\\U000000df\\u03a0\\U00000041", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "ßßΠA"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\073", 0, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, ";"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("A=A\\\\x0aB", 0, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "A=A\\x0aB"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("A=A\\\\x0aB", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "A=A\\x0aB"));
}

static void test_shell_escape_one(const char *s, const char *bad, const char *expected) {
        _cleanup_free_ char *r;

        assert_se(r = shell_escape(s, bad));
        assert_se(streq_ptr(r, expected));
}

static void test_shell_escape(void) {
        test_shell_escape_one("", "", "");
        test_shell_escape_one("\\", "", "\\\\");
        test_shell_escape_one("foobar", "", "foobar");
        test_shell_escape_one("foobar", "o", "f\\o\\obar");
        test_shell_escape_one("foo:bar,baz", ",:", "foo\\:bar\\,baz");
}

static void test_shell_maybe_quote_one(const char *s,
                                       EscapeStyle style,
                                       const char *expected) {
        _cleanup_free_ char *ret = NULL;

        assert_se(ret = shell_maybe_quote(s, style));
        log_debug("[%s] → [%s] (%s)", s, ret, expected);
        assert_se(streq(ret, expected));
}

static void test_shell_maybe_quote(void) {

        test_shell_maybe_quote_one("", ESCAPE_BACKSLASH, "");
        test_shell_maybe_quote_one("", ESCAPE_POSIX, "");
        test_shell_maybe_quote_one("\\", ESCAPE_BACKSLASH, "\"\\\\\"");
        test_shell_maybe_quote_one("\\", ESCAPE_POSIX, "$'\\\\'");
        test_shell_maybe_quote_one("\"", ESCAPE_BACKSLASH, "\"\\\"\"");
        test_shell_maybe_quote_one("\"", ESCAPE_POSIX, "$'\"'");
        test_shell_maybe_quote_one("foobar", ESCAPE_BACKSLASH, "foobar");
        test_shell_maybe_quote_one("foobar", ESCAPE_POSIX, "foobar");
        test_shell_maybe_quote_one("foo bar", ESCAPE_BACKSLASH, "\"foo bar\"");
        test_shell_maybe_quote_one("foo bar", ESCAPE_POSIX, "$'foo bar'");
        test_shell_maybe_quote_one("foo\tbar", ESCAPE_BACKSLASH, "\"foo\tbar\"");
        test_shell_maybe_quote_one("foo\tbar", ESCAPE_POSIX, "$'foo\\tbar'");
        test_shell_maybe_quote_one("foo\nbar", ESCAPE_BACKSLASH, "\"foo\nbar\"");
        test_shell_maybe_quote_one("foo\nbar", ESCAPE_POSIX, "$'foo\\nbar'");
        test_shell_maybe_quote_one("foo \"bar\" waldo", ESCAPE_BACKSLASH, "\"foo \\\"bar\\\" waldo\"");
        test_shell_maybe_quote_one("foo \"bar\" waldo", ESCAPE_POSIX, "$'foo \"bar\" waldo'");
        test_shell_maybe_quote_one("foo$bar", ESCAPE_BACKSLASH, "\"foo\\$bar\"");
        test_shell_maybe_quote_one("foo$bar", ESCAPE_POSIX, "$'foo$bar'");

        /* Note that current users disallow control characters, so this "test"
         * is here merely to establish current behaviour. If control characters
         * were allowed, they should be quoted, i.e. \001 should become \\001. */
        test_shell_maybe_quote_one("a\nb\001", ESCAPE_BACKSLASH, "\"a\nb\001\"");
        test_shell_maybe_quote_one("a\nb\001", ESCAPE_POSIX, "$'a\\nb\001'");

        test_shell_maybe_quote_one("foo!bar", ESCAPE_BACKSLASH, "\"foo!bar\"");
        test_shell_maybe_quote_one("foo!bar", ESCAPE_POSIX, "$'foo!bar'");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_cescape();
        test_xescape();
        test_xescape_full(false);
        test_xescape_full(true);
        test_cunescape();
        test_shell_escape();
        test_shell_maybe_quote();

        return 0;
}
