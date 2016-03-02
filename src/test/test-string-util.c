/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "alloc-util.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

static void test_string_erase(void) {
        char *x;

        x = strdupa("");
        assert_se(streq(string_erase(x), ""));

        x = strdupa("1");
        assert_se(streq(string_erase(x), "x"));

        x = strdupa("12");
        assert_se(streq(string_erase(x), "xx"));

        x = strdupa("123");
        assert_se(streq(string_erase(x), "xxx"));

        x = strdupa("1234");
        assert_se(streq(string_erase(x), "xxxx"));

        x = strdupa("12345");
        assert_se(streq(string_erase(x), "xxxxx"));

        x = strdupa("123456");
        assert_se(streq(string_erase(x), "xxxxxx"));

        x = strdupa("1234567");
        assert_se(streq(string_erase(x), "xxxxxxx"));

        x = strdupa("12345678");
        assert_se(streq(string_erase(x), "xxxxxxxx"));

        x = strdupa("123456789");
        assert_se(streq(string_erase(x), "xxxxxxxxx"));
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
        _cleanup_free_ char *str = strdup("0123");
        strextend(&str, "456", "78", "9", NULL);
        assert_se(streq(str, "0123456789"));
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


static void test_strappend(void) {
        _cleanup_free_ char *t1, *t2, *t3, *t4;

        t1 = strappend(NULL, NULL);
        assert_se(streq(t1, ""));

        t2 = strappend(NULL, "suf");
        assert_se(streq(t2, "suf"));

        t3 = strappend("pre", NULL);
        assert_se(streq(t3, "pre"));

        t4 = strappend("pre", "suf");
        assert_se(streq(t4, "presuf"));
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
        const char *word, *state;
        size_t l;
        int i = 0;

        printf("<<<%s>>>\n", test);
        FOREACH_WORD_QUOTED(word, l, test, state) {
                _cleanup_free_ char *t = NULL;

                assert_se(t = strndup(word, l));
                assert_se(strneq(expected[i++], word, l));
                printf("<%s>\n", t);
        }
        printf("<<<%s>>>\n", state);
        assert_se(expected[i] == NULL);
        assert_se(isempty(state) == !trailing);
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
        char *r;
        char input[] = "   hello, waldo.   abc";

        r = delete_chars(input, WHITESPACE);
        assert_se(streq(r, "hello,waldo.abc"));
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

int main(int argc, char *argv[]) {
        test_string_erase();
        test_ascii_strcasecmp_n();
        test_ascii_strcasecmp_nn();
        test_streq_ptr();
        test_strstrip();
        test_strextend();
        test_strrep();
        test_strappend();
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
        test_in_charset();
        test_split_pair();
        test_first_word();

        return 0;
}
