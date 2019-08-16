/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "locale-util.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "utf8.h"
#include "util.h"

static void test_free_and_strndup_one(char **t, const char *src, size_t l, const char *expected, bool change) {
        int r;

        log_debug("%s: \"%s\", \"%s\", %zd (expect \"%s\", %s)",
                  __func__, strnull(*t), strnull(src), l, strnull(expected), yes_no(change));

        r = free_and_strndup(t, src, l);
        assert_se(streq_ptr(*t, expected));
        assert_se(r == change); /* check that change occurs only when necessary */
}

static void test_free_and_strndup(void) {
        static const struct test_case {
                const char *src;
                size_t len;
                const char *expected;
        } cases[] = {
                     {"abc", 0, ""},
                     {"abc", 0, ""},
                     {"abc", 1, "a"},
                     {"abc", 2, "ab"},
                     {"abc", 3, "abc"},
                     {"abc", 4, "abc"},
                     {"abc", 5, "abc"},
                     {"abc", 5, "abc"},
                     {"abc", 4, "abc"},
                     {"abc", 3, "abc"},
                     {"abc", 2, "ab"},
                     {"abc", 1, "a"},
                     {"abc", 0, ""},

                     {"", 0, ""},
                     {"", 1, ""},
                     {"", 2, ""},
                     {"", 0, ""},
                     {"", 1, ""},
                     {"", 2, ""},
                     {"", 2, ""},
                     {"", 1, ""},
                     {"", 0, ""},

                     {NULL, 0, NULL},

                     {"foo", 3, "foo"},
                     {"foobar", 6, "foobar"},
        };

        _cleanup_free_ char *t = NULL;
        const char *prev_expected = t;

        for (unsigned i = 0; i < ELEMENTSOF(cases); i++) {
                test_free_and_strndup_one(&t,
                                          cases[i].src, cases[i].len, cases[i].expected,
                                          !streq_ptr(cases[i].expected, prev_expected));
                prev_expected = t;
        }
}

static void test_ascii_strcasecmp_n(void) {

        assert_se(ascii_strcasecmp_n("", "", 0) == 0);
        assert_se(ascii_strcasecmp_n("", "", 1) == 0);
        assert_se(ascii_strcasecmp_n("", "a", 1) < 0);
        assert_se(ascii_strcasecmp_n("", "a", 2) < 0);
        assert_se(ascii_strcasecmp_n("a", "", 1) > 0);
        assert_se(ascii_strcasecmp_n("a", "", 2) > 0);
        assert_se(ascii_strcasecmp_n("a", "a", 1) == 0);
        assert_se(ascii_strcasecmp_n("a", "a", 2) == 0);
        assert_se(ascii_strcasecmp_n("a", "b", 1) < 0);
        assert_se(ascii_strcasecmp_n("a", "b", 2) < 0);
        assert_se(ascii_strcasecmp_n("b", "a", 1) > 0);
        assert_se(ascii_strcasecmp_n("b", "a", 2) > 0);
        assert_se(ascii_strcasecmp_n("xxxxyxxxx", "xxxxYxxxx", 9) == 0);
        assert_se(ascii_strcasecmp_n("xxxxxxxxx", "xxxxyxxxx", 9) < 0);
        assert_se(ascii_strcasecmp_n("xxxxXxxxx", "xxxxyxxxx", 9) < 0);
        assert_se(ascii_strcasecmp_n("xxxxxxxxx", "xxxxYxxxx", 9) < 0);
        assert_se(ascii_strcasecmp_n("xxxxXxxxx", "xxxxYxxxx", 9) < 0);

        assert_se(ascii_strcasecmp_n("xxxxYxxxx", "xxxxYxxxx", 9) == 0);
        assert_se(ascii_strcasecmp_n("xxxxyxxxx", "xxxxxxxxx", 9) > 0);
        assert_se(ascii_strcasecmp_n("xxxxyxxxx", "xxxxXxxxx", 9) > 0);
        assert_se(ascii_strcasecmp_n("xxxxYxxxx", "xxxxxxxxx", 9) > 0);
        assert_se(ascii_strcasecmp_n("xxxxYxxxx", "xxxxXxxxx", 9) > 0);
}

static void test_ascii_strcasecmp_nn(void) {
        assert_se(ascii_strcasecmp_nn("", 0, "", 0) == 0);
        assert_se(ascii_strcasecmp_nn("", 0, "", 1) < 0);
        assert_se(ascii_strcasecmp_nn("", 1, "", 0) > 0);
        assert_se(ascii_strcasecmp_nn("", 1, "", 1) == 0);

        assert_se(ascii_strcasecmp_nn("aaaa", 4, "aaAa", 4) == 0);
        assert_se(ascii_strcasecmp_nn("aaa", 3, "aaAa", 4) < 0);
        assert_se(ascii_strcasecmp_nn("aaa", 4, "aaAa", 4) < 0);
        assert_se(ascii_strcasecmp_nn("aaaa", 4, "aaA", 3) > 0);
        assert_se(ascii_strcasecmp_nn("aaaa", 4, "AAA", 4) > 0);

        assert_se(ascii_strcasecmp_nn("aaaa", 4, "bbbb", 4) < 0);
        assert_se(ascii_strcasecmp_nn("aaAA", 4, "BBbb", 4) < 0);
        assert_se(ascii_strcasecmp_nn("BBbb", 4, "aaaa", 4) > 0);
}

static void test_cellescape(void) {
        char buf[40];

        assert_se(streq(cellescape(buf, 1, ""), ""));
        assert_se(streq(cellescape(buf, 1, "1"), ""));
        assert_se(streq(cellescape(buf, 1, "12"), ""));

        assert_se(streq(cellescape(buf, 2, ""), ""));
        assert_se(streq(cellescape(buf, 2, "1"), "1"));
        assert_se(streq(cellescape(buf, 2, "12"), "."));
        assert_se(streq(cellescape(buf, 2, "123"), "."));

        assert_se(streq(cellescape(buf, 3, ""), ""));
        assert_se(streq(cellescape(buf, 3, "1"), "1"));
        assert_se(streq(cellescape(buf, 3, "12"), "12"));
        assert_se(streq(cellescape(buf, 3, "123"), ".."));
        assert_se(streq(cellescape(buf, 3, "1234"), ".."));

        assert_se(streq(cellescape(buf, 4, ""), ""));
        assert_se(streq(cellescape(buf, 4, "1"), "1"));
        assert_se(streq(cellescape(buf, 4, "12"), "12"));
        assert_se(streq(cellescape(buf, 4, "123"), "123"));
        assert_se(streq(cellescape(buf, 4, "1234"), is_locale_utf8() ? "…" : "..."));
        assert_se(streq(cellescape(buf, 4, "12345"), is_locale_utf8() ? "…" : "..."));

        assert_se(streq(cellescape(buf, 5, ""), ""));
        assert_se(streq(cellescape(buf, 5, "1"), "1"));
        assert_se(streq(cellescape(buf, 5, "12"), "12"));
        assert_se(streq(cellescape(buf, 5, "123"), "123"));
        assert_se(streq(cellescape(buf, 5, "1234"), "1234"));
        assert_se(streq(cellescape(buf, 5, "12345"), is_locale_utf8() ? "1…" : "1..."));
        assert_se(streq(cellescape(buf, 5, "123456"), is_locale_utf8() ? "1…" : "1..."));

        assert_se(streq(cellescape(buf, 1, "\020"), ""));
        assert_se(streq(cellescape(buf, 2, "\020"), "."));
        assert_se(streq(cellescape(buf, 3, "\020"), ".."));
        assert_se(streq(cellescape(buf, 4, "\020"), "…"));
        assert_se(streq(cellescape(buf, 5, "\020"), "\\020"));

        assert_se(streq(cellescape(buf, 5, "1234\020"), "1…"));
        assert_se(streq(cellescape(buf, 6, "1234\020"), "12…"));
        assert_se(streq(cellescape(buf, 7, "1234\020"), "123…"));
        assert_se(streq(cellescape(buf, 8, "1234\020"), "1234…"));
        assert_se(streq(cellescape(buf, 9, "1234\020"), "1234\\020"));

        assert_se(streq(cellescape(buf, 1, "\t\n"), ""));
        assert_se(streq(cellescape(buf, 2, "\t\n"), "."));
        assert_se(streq(cellescape(buf, 3, "\t\n"), ".."));
        assert_se(streq(cellescape(buf, 4, "\t\n"), "…"));
        assert_se(streq(cellescape(buf, 5, "\t\n"), "\\t\\n"));

        assert_se(streq(cellescape(buf, 5, "1234\t\n"), "1…"));
        assert_se(streq(cellescape(buf, 6, "1234\t\n"), "12…"));
        assert_se(streq(cellescape(buf, 7, "1234\t\n"), "123…"));
        assert_se(streq(cellescape(buf, 8, "1234\t\n"), "1234…"));
        assert_se(streq(cellescape(buf, 9, "1234\t\n"), "1234\\t\\n"));

        assert_se(streq(cellescape(buf, 4, "x\t\020\n"), "…"));
        assert_se(streq(cellescape(buf, 5, "x\t\020\n"), "x…"));
        assert_se(streq(cellescape(buf, 6, "x\t\020\n"), "x…"));
        assert_se(streq(cellescape(buf, 7, "x\t\020\n"), "x\\t…"));
        assert_se(streq(cellescape(buf, 8, "x\t\020\n"), "x\\t…"));
        assert_se(streq(cellescape(buf, 9, "x\t\020\n"), "x\\t…"));
        assert_se(streq(cellescape(buf, 10, "x\t\020\n"), "x\\t\\020\\n"));

        assert_se(streq(cellescape(buf, 6, "1\011"), "1\\t"));
        assert_se(streq(cellescape(buf, 6, "1\020"), "1\\020"));
        assert_se(streq(cellescape(buf, 6, "1\020x"), is_locale_utf8() ? "1…" : "1..."));

        assert_se(streq(cellescape(buf, 40, "1\020"), "1\\020"));
        assert_se(streq(cellescape(buf, 40, "1\020x"), "1\\020x"));

        assert_se(streq(cellescape(buf, 40, "\a\b\f\n\r\t\v\\\"'"), "\\a\\b\\f\\n\\r\\t\\v\\\\\\\"\\'"));
        assert_se(streq(cellescape(buf, 6, "\a\b\f\n\r\t\v\\\"'"), is_locale_utf8() ? "\\a…" : "\\a..."));
        assert_se(streq(cellescape(buf, 7, "\a\b\f\n\r\t\v\\\"'"), is_locale_utf8() ? "\\a…" : "\\a..."));
        assert_se(streq(cellescape(buf, 8, "\a\b\f\n\r\t\v\\\"'"), is_locale_utf8() ? "\\a\\b…" : "\\a\\b..."));

        assert_se(streq(cellescape(buf, sizeof buf, "1\020"), "1\\020"));
        assert_se(streq(cellescape(buf, sizeof buf, "1\020x"), "1\\020x"));
}

static void test_streq_ptr(void) {
        assert_se(streq_ptr(NULL, NULL));
        assert_se(!streq_ptr("abc", "cdef"));
}

static void test_strstrip(void) {
        char *r;
        char input[] = "   hello, waldo.   ";

        r = strstrip(input);
        assert_se(streq(r, "hello, waldo."));
}

static void test_strextend(void) {
        _cleanup_free_ char *str = NULL;

        assert_se(strextend(&str, NULL));
        assert_se(streq_ptr(str, ""));
        assert_se(strextend(&str, "", "0", "", "", "123", NULL));
        assert_se(streq_ptr(str, "0123"));
        assert_se(strextend(&str, "456", "78", "9", NULL));
        assert_se(streq_ptr(str, "0123456789"));
}

static void test_strextend_with_separator(void) {
        _cleanup_free_ char *str = NULL;

        assert_se(strextend_with_separator(&str, NULL, NULL));
        assert_se(streq_ptr(str, ""));
        str = mfree(str);

        assert_se(strextend_with_separator(&str, "...", NULL));
        assert_se(streq_ptr(str, ""));
        assert_se(strextend_with_separator(&str, "...", NULL));
        assert_se(streq_ptr(str, ""));
        str = mfree(str);

        assert_se(strextend_with_separator(&str, "xyz", "a", "bb", "ccc", NULL));
        assert_se(streq_ptr(str, "axyzbbxyzccc"));
        str = mfree(str);

        assert_se(strextend_with_separator(&str, ",", "start", "", "1", "234", NULL));
        assert_se(streq_ptr(str, "start,,1,234"));
        assert_se(strextend_with_separator(&str, ";", "more", "5", "678", NULL));
        assert_se(streq_ptr(str, "start,,1,234;more;5;678"));
}

static void test_strrep(void) {
        _cleanup_free_ char *one, *three, *zero;
        one = strrep("waldo", 1);
        three = strrep("waldo", 3);
        zero = strrep("waldo", 0);

        assert_se(streq(one, "waldo"));
        assert_se(streq(three, "waldowaldowaldo"));
        assert_se(streq(zero, ""));
}

static void test_string_has_cc(void) {
        assert_se(string_has_cc("abc\1", NULL));
        assert_se(string_has_cc("abc\x7f", NULL));
        assert_se(string_has_cc("abc\x7f", NULL));
        assert_se(string_has_cc("abc\t\x7f", "\t"));
        assert_se(string_has_cc("abc\t\x7f", "\t"));
        assert_se(string_has_cc("\x7f", "\t"));
        assert_se(string_has_cc("\x7f", "\t\a"));

        assert_se(!string_has_cc("abc\t\t", "\t"));
        assert_se(!string_has_cc("abc\t\t\a", "\t\a"));
        assert_se(!string_has_cc("a\ab\tc", "\t\a"));
}

static void test_ascii_strlower(void) {
        char a[] = "AabBcC Jk Ii Od LKJJJ kkd LK";
        assert_se(streq(ascii_strlower(a), "aabbcc jk ii od lkjjj kkd lk"));
}

static void test_strshorten(void) {
        char s[] = "foobar";

        assert_se(strlen(strshorten(s, 6)) == 6);
        assert_se(strlen(strshorten(s, 12)) == 6);
        assert_se(strlen(strshorten(s, 2)) == 2);
        assert_se(strlen(strshorten(s, 0)) == 0);
}

static void test_strjoina(void) {
        char *actual;

        actual = strjoina("", "foo", "bar");
        assert_se(streq(actual, "foobar"));

        actual = strjoina("foo", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));

        actual = strjoina("foo", "", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));

        actual = strjoina("foo");
        assert_se(streq(actual, "foo"));

        actual = strjoina(NULL);
        assert_se(streq(actual, ""));

        actual = strjoina(NULL, "foo");
        assert_se(streq(actual, ""));

        actual = strjoina("foo", NULL, "bar");
        assert_se(streq(actual, "foo"));
}

static void test_strcmp_ptr(void) {
        assert_se(strcmp_ptr(NULL, NULL) == 0);
        assert_se(strcmp_ptr("", NULL) > 0);
        assert_se(strcmp_ptr("foo", NULL) > 0);
        assert_se(strcmp_ptr(NULL, "") < 0);
        assert_se(strcmp_ptr(NULL, "bar") < 0);
        assert_se(strcmp_ptr("foo", "bar") > 0);
        assert_se(strcmp_ptr("bar", "baz") < 0);
        assert_se(strcmp_ptr("foo", "foo") == 0);
        assert_se(strcmp_ptr("", "") == 0);
}

static void test_foreach_word(void) {
        const char *word, *state;
        size_t l;
        int i = 0;
        const char test[] = "test abc d\te   f   ";
        const char * const expected[] = {
                "test",
                "abc",
                "d",
                "e",
                "f",
                "",
                NULL
        };

        FOREACH_WORD(word, l, test, state)
                assert_se(strneq(expected[i++], word, l));
}

static void check(const char *test, char** expected, bool trailing) {
        int i = 0, r;

        printf("<<<%s>>>\n", test);
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&test, &word, NULL, EXTRACT_UNQUOTE);
                if (r == 0) {
                        assert_se(!trailing);
                        break;
                } else if (r < 0) {
                        assert_se(trailing);
                        break;
                }

                assert_se(streq(word, expected[i++]));
                printf("<%s>\n", word);
        }
        assert_se(expected[i] == NULL);
}

static void test_foreach_word_quoted(void) {
        check("test a b c 'd' e '' '' hhh '' '' \"a b c\"",
              STRV_MAKE("test",
                        "a",
                        "b",
                        "c",
                        "d",
                        "e",
                        "",
                        "",
                        "hhh",
                        "",
                        "",
                        "a b c"),
              false);

        check("test \"xxx",
              STRV_MAKE("test"),
              true);

        check("test\\",
              STRV_MAKE_EMPTY,
              true);
}

static void test_endswith(void) {
        assert_se(endswith("foobar", "bar"));
        assert_se(endswith("foobar", ""));
        assert_se(endswith("foobar", "foobar"));
        assert_se(endswith("", ""));

        assert_se(!endswith("foobar", "foo"));
        assert_se(!endswith("foobar", "foobarfoofoo"));
}

static void test_endswith_no_case(void) {
        assert_se(endswith_no_case("fooBAR", "bar"));
        assert_se(endswith_no_case("foobar", ""));
        assert_se(endswith_no_case("foobar", "FOOBAR"));
        assert_se(endswith_no_case("", ""));

        assert_se(!endswith_no_case("foobar", "FOO"));
        assert_se(!endswith_no_case("foobar", "FOOBARFOOFOO"));
}

static void test_delete_chars(void) {
        char *s, input[] = "   hello, waldo.   abc";

        s = delete_chars(input, WHITESPACE);
        assert_se(streq(s, "hello,waldo.abc"));
        assert_se(s == input);
}

static void test_delete_trailing_chars(void) {

        char *s,
                input1[] = " \n \r k \n \r ",
                input2[] = "kkkkthiskkkiskkkaktestkkk",
                input3[] = "abcdef";

        s = delete_trailing_chars(input1, WHITESPACE);
        assert_se(streq(s, " \n \r k"));
        assert_se(s == input1);

        s = delete_trailing_chars(input2, "kt");
        assert_se(streq(s, "kkkkthiskkkiskkkaktes"));
        assert_se(s == input2);

        s = delete_trailing_chars(input3, WHITESPACE);
        assert_se(streq(s, "abcdef"));
        assert_se(s == input3);

        s = delete_trailing_chars(input3, "fe");
        assert_se(streq(s, "abcd"));
        assert_se(s == input3);
}

static void test_delete_trailing_slashes(void) {
        char s1[] = "foobar//",
             s2[] = "foobar/",
             s3[] = "foobar",
             s4[] = "";

        assert_se(streq(delete_trailing_chars(s1, "_"), "foobar//"));
        assert_se(streq(delete_trailing_chars(s1, "/"), "foobar"));
        assert_se(streq(delete_trailing_chars(s2, "/"), "foobar"));
        assert_se(streq(delete_trailing_chars(s3, "/"), "foobar"));
        assert_se(streq(delete_trailing_chars(s4, "/"), ""));
}

static void test_skip_leading_chars(void) {
        char input1[] = " \n \r k \n \r ",
                input2[] = "kkkkthiskkkiskkkaktestkkk",
                input3[] = "abcdef";

        assert_se(streq(skip_leading_chars(input1, WHITESPACE), "k \n \r "));
        assert_se(streq(skip_leading_chars(input2, "k"), "thiskkkiskkkaktestkkk"));
        assert_se(streq(skip_leading_chars(input2, "tk"), "hiskkkiskkkaktestkkk"));
        assert_se(streq(skip_leading_chars(input3, WHITESPACE), "abcdef"));
        assert_se(streq(skip_leading_chars(input3, "bcaef"), "def"));
}

static void test_in_charset(void) {
        assert_se(in_charset("dddaaabbbcccc", "abcd"));
        assert_se(!in_charset("dddaaabbbcccc", "abc f"));
}

static void test_split_pair(void) {
        _cleanup_free_ char *a = NULL, *b = NULL;

        assert_se(split_pair("", "", &a, &b) == -EINVAL);
        assert_se(split_pair("foo=bar", "", &a, &b) == -EINVAL);
        assert_se(split_pair("", "=", &a, &b) == -EINVAL);
        assert_se(split_pair("foo=bar", "=", &a, &b) >= 0);
        assert_se(streq(a, "foo"));
        assert_se(streq(b, "bar"));
        free(a);
        free(b);
        assert_se(split_pair("==", "==", &a, &b) >= 0);
        assert_se(streq(a, ""));
        assert_se(streq(b, ""));
        free(a);
        free(b);

        assert_se(split_pair("===", "==", &a, &b) >= 0);
        assert_se(streq(a, ""));
        assert_se(streq(b, "="));
}

static void test_first_word(void) {
        assert_se(first_word("Hello", ""));
        assert_se(first_word("Hello", "Hello"));
        assert_se(first_word("Hello world", "Hello"));
        assert_se(first_word("Hello\tworld", "Hello"));
        assert_se(first_word("Hello\nworld", "Hello"));
        assert_se(first_word("Hello\rworld", "Hello"));
        assert_se(first_word("Hello ", "Hello"));

        assert_se(!first_word("Hello", "Hellooo"));
        assert_se(!first_word("Hello", "xxxxx"));
        assert_se(!first_word("Hellooo", "Hello"));
}

static void test_strlen_ptr(void) {
        assert_se(strlen_ptr("foo") == 3);
        assert_se(strlen_ptr("") == 0);
        assert_se(strlen_ptr(NULL) == 0);
}

static void test_memory_startswith(void) {
        assert_se(streq(memory_startswith("", 0, ""), ""));
        assert_se(streq(memory_startswith("", 1, ""), ""));
        assert_se(streq(memory_startswith("x", 2, ""), "x"));
        assert_se(!memory_startswith("", 1, "x"));
        assert_se(!memory_startswith("", 1, "xxxxxxxx"));
        assert_se(streq(memory_startswith("xxx", 4, "x"), "xx"));
        assert_se(streq(memory_startswith("xxx", 4, "xx"), "x"));
        assert_se(streq(memory_startswith("xxx", 4, "xxx"), ""));
        assert_se(!memory_startswith("xxx", 4, "xxxx"));
}

static void test_memory_startswith_no_case(void) {
        assert_se(streq(memory_startswith_no_case("", 0, ""), ""));
        assert_se(streq(memory_startswith_no_case("", 1, ""), ""));
        assert_se(streq(memory_startswith_no_case("x", 2, ""), "x"));
        assert_se(streq(memory_startswith_no_case("X", 2, ""), "X"));
        assert_se(!memory_startswith_no_case("", 1, "X"));
        assert_se(!memory_startswith_no_case("", 1, "xxxxXXXX"));
        assert_se(streq(memory_startswith_no_case("xxx", 4, "X"), "xx"));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "x"), "XX"));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "X"), "XX"));
        assert_se(streq(memory_startswith_no_case("xxx", 4, "XX"), "x"));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "xx"), "X"));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "XX"), "X"));
        assert_se(streq(memory_startswith_no_case("xxx", 4, "XXX"), ""));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "xxx"), ""));
        assert_se(streq(memory_startswith_no_case("XXX", 4, "XXX"), ""));

        assert_se(memory_startswith_no_case((char[2]){'x', 'x'}, 2, "xx"));
        assert_se(memory_startswith_no_case((char[2]){'x', 'X'}, 2, "xX"));
        assert_se(memory_startswith_no_case((char[2]){'X', 'x'}, 2, "Xx"));
        assert_se(memory_startswith_no_case((char[2]){'X', 'X'}, 2, "XX"));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_free_and_strndup();
        test_ascii_strcasecmp_n();
        test_ascii_strcasecmp_nn();
        test_cellescape();
        test_streq_ptr();
        test_strstrip();
        test_strextend();
        test_strextend_with_separator();
        test_strrep();
        test_string_has_cc();
        test_ascii_strlower();
        test_strshorten();
        test_strjoina();
        test_strcmp_ptr();
        test_foreach_word();
        test_foreach_word_quoted();
        test_endswith();
        test_endswith_no_case();
        test_delete_chars();
        test_delete_trailing_chars();
        test_delete_trailing_slashes();
        test_skip_leading_chars();
        test_in_charset();
        test_split_pair();
        test_first_word();
        test_strlen_ptr();
        test_memory_startswith();
        test_memory_startswith_no_case();

        return 0;
}
