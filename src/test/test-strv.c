/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(str_in_set) {
        assert_se(STR_IN_SET("x", "x", "y", "z"));
        assert_se(!STR_IN_SET("X", "x", "y", "z"));
        assert_se(!STR_IN_SET("", "x", "y", "z"));
        assert_se(STR_IN_SET("x", "w", "x"));
}

TEST(strptr_in_set) {
        assert_se(STRPTR_IN_SET("x", "x", "y", "z"));
        assert_se(!STRPTR_IN_SET("X", "x", "y", "z"));
        assert_se(!STRPTR_IN_SET("", "x", "y", "z"));
        assert_se(STRPTR_IN_SET("x", "w", "x"));

        assert_se(!STRPTR_IN_SET(NULL, "x", "y", "z"));
        assert_se(!STRPTR_IN_SET(NULL, ""));
        /* strv cannot contain a null, hence the result below */
        assert_se(!STRPTR_IN_SET(NULL, NULL));
}

TEST(startswith_set) {
        assert_se(!STARTSWITH_SET("foo", "bar", "baz", "waldo"));
        assert_se(!STARTSWITH_SET("foo", "bar"));

        assert_se(STARTSWITH_SET("abc", "a", "ab", "abc"));
        assert_se(STARTSWITH_SET("abc", "ax", "ab", "abc"));
        assert_se(STARTSWITH_SET("abc", "ax", "abx", "abc"));
        assert_se(!STARTSWITH_SET("abc", "ax", "abx", "abcx"));

        ASSERT_STREQ(STARTSWITH_SET("foobar", "hhh", "kkk", "foo", "zzz"), "bar");
        ASSERT_STREQ(STARTSWITH_SET("foobar", "hhh", "kkk", "", "zzz"), "foobar");
        ASSERT_STREQ(STARTSWITH_SET("", "hhh", "kkk", "zzz", ""), "");
}

static const char* const input_table_multiple[] = {
        "one",
        "two",
        "three",
        NULL,
};

static const char* const input_table_quoted[] = {
        "one",
        "  two\t three ",
        " four  five",
        NULL,
};

static const char* const input_table_quoted_joined[] = {
        "one",
        "  two\t three " " four  five",
        NULL,
};

static const char* const input_table_one[] = {
        "one",
        NULL,
};

static const char* const input_table_none[] = {
        NULL,
};

static const char* const input_table_two_empties[] = {
        "",
        "",
        NULL,
};

static const char* const input_table_one_empty[] = {
        "",
        NULL,
};

static const char* const input_table_unescape[] = {
        "ID_VENDOR=QEMU",
        "ID_VENDOR_ENC=QEMUx20x20x20x20",
        "ID_MODEL_ENC=QEMUx20HARDDISKx20x20x20",
        NULL,
};

static const char* const input_table_retain_escape[] = {
        "ID_VENDOR=QEMU",
        "ID_VENDOR_ENC=QEMU\\x20\\x20\\x20\\x20",
        "ID_MODEL_ENC=QEMU\\x20HARDDISK\\x20\\x20\\x20",
        NULL,
};

TEST(strv_find) {
        assert_se(strv_find((char **)input_table_multiple, "three"));
        assert_se(!strv_find((char **)input_table_multiple, "four"));
}

TEST(strv_find_prefix) {
        assert_se(strv_find_prefix((char **)input_table_multiple, "o"));
        assert_se(strv_find_prefix((char **)input_table_multiple, "one"));
        assert_se(strv_find_prefix((char **)input_table_multiple, ""));
        assert_se(!strv_find_prefix((char **)input_table_multiple, "xxx"));
        assert_se(!strv_find_prefix((char **)input_table_multiple, "onee"));
}

TEST(strv_find_startswith) {
        char *r;

        r = strv_find_startswith((char **)input_table_multiple, "o");
        assert_se(r && streq(r, "ne"));

        r = strv_find_startswith((char **)input_table_multiple, "one");
        assert_se(r && streq(r, ""));

        r = strv_find_startswith((char **)input_table_multiple, "");
        assert_se(r && streq(r, "one"));

        assert_se(!strv_find_startswith((char **)input_table_multiple, "xxx"));
        assert_se(!strv_find_startswith((char **)input_table_multiple, "onee"));
}

TEST(strv_join) {
        _cleanup_free_ char *p = strv_join((char **)input_table_multiple, ", ");
        assert_se(p);
        ASSERT_STREQ(p, "one, two, three");

        _cleanup_free_ char *q = strv_join((char **)input_table_multiple, ";");
        assert_se(q);
        ASSERT_STREQ(q, "one;two;three");

        _cleanup_free_ char *r = strv_join((char **)input_table_multiple, NULL);
        assert_se(r);
        ASSERT_STREQ(r, "one two three");

        _cleanup_free_ char *s = strv_join(STRV_MAKE("1", "2", "3,3"), ",");
        assert_se(s);
        ASSERT_STREQ(s, "1,2,3,3");

        _cleanup_free_ char *t = strv_join((char **)input_table_one, ", ");
        assert_se(t);
        ASSERT_STREQ(t, "one");

        _cleanup_free_ char *u = strv_join((char **)input_table_none, ", ");
        assert_se(u);
        ASSERT_STREQ(u, "");

        _cleanup_free_ char *v = strv_join((char **)input_table_two_empties, ", ");
        assert_se(v);
        ASSERT_STREQ(v, ", ");

        _cleanup_free_ char *w = strv_join((char **)input_table_one_empty, ", ");
        assert_se(w);
        ASSERT_STREQ(w, "");
}

TEST(strv_join_full) {
        _cleanup_free_ char *p = strv_join_full((char **)input_table_multiple, ", ", "foo", false);
        assert_se(p);
        ASSERT_STREQ(p, "fooone, footwo, foothree");

        _cleanup_free_ char *q = strv_join_full((char **)input_table_multiple, ";", "foo", false);
        assert_se(q);
        ASSERT_STREQ(q, "fooone;footwo;foothree");

        _cleanup_free_ char *r = strv_join_full(STRV_MAKE("a", "a;b", "a:c"), ";", NULL, true);
        assert_se(r);
        ASSERT_STREQ(r, "a;a\\;b;a:c");

        _cleanup_free_ char *s = strv_join_full(STRV_MAKE("a", "a;b", "a;;c", ";", ";x"), ";", NULL, true);
        assert_se(s);
        ASSERT_STREQ(s, "a;a\\;b;a\\;\\;c;\\;;\\;x");

        _cleanup_free_ char *t = strv_join_full(STRV_MAKE("a", "a;b", "a:c", ";"), ";", "=", true);
        assert_se(t);
        ASSERT_STREQ(t, "=a;=a\\;b;=a:c;=\\;");
        t = mfree(t);

        _cleanup_free_ char *u = strv_join_full((char **)input_table_multiple, NULL, "foo", false);
        assert_se(u);
        ASSERT_STREQ(u, "fooone footwo foothree");

        _cleanup_free_ char *v = strv_join_full((char **)input_table_one, ", ", "foo", false);
        assert_se(v);
        ASSERT_STREQ(v, "fooone");

        _cleanup_free_ char *w = strv_join_full((char **)input_table_none, ", ", "foo", false);
        assert_se(w);
        ASSERT_STREQ(w, "");

        _cleanup_free_ char *x = strv_join_full((char **)input_table_two_empties, ", ", "foo", false);
        assert_se(x);
        ASSERT_STREQ(x, "foo, foo");

        _cleanup_free_ char *y = strv_join_full((char **)input_table_one_empty, ", ", "foo", false);
        assert_se(y);
        ASSERT_STREQ(y, "foo");
}

static void test_strv_unquote_one(const char *quoted, char **list) {
        _cleanup_strv_free_ char **s = NULL;
        _cleanup_free_ char *j = NULL;
        unsigned i = 0;
        int r;

        log_info("/* %s */", __func__);

        r = strv_split_full(&s, quoted, WHITESPACE, EXTRACT_UNQUOTE);
        assert_se(r == (int) strv_length(list));
        assert_se(s);
        j = strv_join(s, " | ");
        assert_se(j);
        puts(j);

        STRV_FOREACH(t, s)
                ASSERT_STREQ(list[i++], *t);

        ASSERT_NULL(list[i]);
}

TEST(strv_unquote) {
        test_strv_unquote_one("    foo=bar     \"waldo\"    zzz    ", STRV_MAKE("foo=bar", "waldo", "zzz"));
        test_strv_unquote_one("", STRV_MAKE_EMPTY);
        test_strv_unquote_one(" ", STRV_MAKE_EMPTY);
        test_strv_unquote_one("   ", STRV_MAKE_EMPTY);
        test_strv_unquote_one("   x", STRV_MAKE("x"));
        test_strv_unquote_one("x   ", STRV_MAKE("x"));
        test_strv_unquote_one("  x   ", STRV_MAKE("x"));
        test_strv_unquote_one("  \"x\"   ", STRV_MAKE("x"));
        test_strv_unquote_one("  'x'   ", STRV_MAKE("x"));
        test_strv_unquote_one("  'x\"'   ", STRV_MAKE("x\""));
        test_strv_unquote_one("  \"x'\"   ", STRV_MAKE("x'"));
        test_strv_unquote_one("a  '--b=c \"d e\"'", STRV_MAKE("a", "--b=c \"d e\""));

        /* trailing backslashes */
        test_strv_unquote_one("  x\\\\", STRV_MAKE("x\\"));
}

static void test_invalid_unquote_one(const char *quoted) {
        char **s = NULL;
        int r;

        log_info("/* %s */", __func__);

        r = strv_split_full(&s, quoted, WHITESPACE, EXTRACT_UNQUOTE);
        ASSERT_NULL(s);
        assert_se(r == -EINVAL);
}

TEST(invalid_unquote) {
        test_invalid_unquote_one("  x\\");
        test_invalid_unquote_one("a  --b='c \"d e\"''");
        test_invalid_unquote_one("a  --b='c \"d e\" '\"");
        test_invalid_unquote_one("a  --b='c \"d e\"garbage");
        test_invalid_unquote_one("'");
        test_invalid_unquote_one("\"");
        test_invalid_unquote_one("'x'y'g");
}

TEST(strv_split) {
        _cleanup_strv_free_erase_ char **l = NULL;
        const char str[] = "one,two,three";

        l = strv_split(str, ",");
        assert_se(l);
        assert_se(strv_equal(l, (char**) input_table_multiple));

        strv_free_erase(l);

        l = strv_split("    one    two\t three", WHITESPACE);
        assert_se(l);
        assert_se(strv_equal(l, (char**) input_table_multiple));

        strv_free_erase(l);

        /* Setting NULL for separator is equivalent to WHITESPACE */
        l = strv_split("    one    two\t three", NULL);
        assert_se(l);
        assert_se(strv_equal(l, (char**) input_table_multiple));

        strv_free_erase(l);

        assert_se(strv_split_full(&l, "    one    two\t three", NULL, 0) == 3);
        assert_se(strv_equal(l, (char**) input_table_multiple));

        strv_free_erase(l);

        assert_se(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five'", NULL, EXTRACT_UNQUOTE) == 3);
        assert_se(strv_equal(l, (char**) input_table_quoted));

        l = strv_free_erase(l);

        /* missing last quote causes extraction to fail. */
        assert_se(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five", NULL, EXTRACT_UNQUOTE) == -EINVAL);
        assert_se(!l);

        /* missing last quote, but the last element is _not_ ignored with EXTRACT_RELAX. */
        assert_se(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five", NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX) == 3);
        assert_se(strv_equal(l, (char**) input_table_quoted));

        l = strv_free_erase(l);

        /* missing separator between items */
        assert_se(strv_split_full(&l, "    'one'  \"  two\t three \"' four  five'", NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX) == 2);
        assert_se(strv_equal(l, (char**) input_table_quoted_joined));

        l = strv_free_erase(l);

        assert_se(strv_split_full(&l, "    'one'  \"  two\t three \"' four  five", NULL,
                                     EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_UNESCAPE_RELAX) == 2);
        assert_se(strv_equal(l, (char**) input_table_quoted_joined));

        l = strv_free_erase(l);

        assert_se(strv_split_full(&l, "\\", NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_UNESCAPE_RELAX) == 1);
        assert_se(strv_equal(l, STRV_MAKE("\\")));

        l = strv_free_erase(l);

        assert_se(l = strv_split("\\", NULL));
        assert_se(strv_equal(l, STRV_MAKE("\\")));

        l = strv_free_erase(l);

        assert_se(l = strv_split("aa\\ bb\\", NULL));
        assert_se(strv_equal(l, STRV_MAKE("aa\\", "bb\\")));

        l = strv_free_erase(l);

        assert_se(l = strv_split("aa\" bb'", NULL));
        assert_se(strv_equal(l, STRV_MAKE("aa\"", "bb'")));
}

TEST(strv_split_empty) {
        _cleanup_strv_free_ char **l = NULL;

        l = strv_split("", WHITESPACE);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(l = strv_split("", NULL));
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "", NULL, 0) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "", NULL, EXTRACT_UNQUOTE) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "", WHITESPACE, EXTRACT_UNQUOTE) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "", WHITESPACE, EXTRACT_UNQUOTE | EXTRACT_RELAX) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        strv_free(l);

        l = strv_split("    ", WHITESPACE);
        assert_se(l);
        assert_se(strv_isempty(l));
        strv_free(l);

        l = strv_split("    ", NULL);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "    ", NULL, 0) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "    ", WHITESPACE, EXTRACT_UNQUOTE) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "    ", NULL, EXTRACT_UNQUOTE) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
        l = strv_free(l);

        assert_se(strv_split_full(&l, "    ", NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX) == 0);
        assert_se(l);
        assert_se(strv_isempty(l));
}

TEST(strv_split_full) {
        _cleanup_strv_free_ char **l = NULL;
        const char *str = ":foo\\:bar::waldo:";
        int r;

        r = strv_split_full(&l, str, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        assert_se(r == (int) strv_length(l));
        ASSERT_STREQ(l[0], "");
        ASSERT_STREQ(l[1], "foo:bar");
        ASSERT_STREQ(l[2], "");
        ASSERT_STREQ(l[3], "waldo");
        ASSERT_STREQ(l[4], "");
        ASSERT_STREQ(l[5], NULL);
}

TEST(strv_split_and_extend_full) {
        _cleanup_strv_free_ char **l = NULL;
        const char *str1 = ":foo\\:bar:";
        const char *str2 = "waldo::::::baz";
        int r;

        r = strv_split_and_extend(&l, "", ":", false);
        assert_se(r == (int) strv_length(l));
        r = strv_split_and_extend_full(&l, str1, ":", false, EXTRACT_DONT_COALESCE_SEPARATORS);
        assert_se(r == (int) strv_length(l));
        ASSERT_STREQ(l[0], "");
        ASSERT_STREQ(l[1], "foo:bar");
        ASSERT_STREQ(l[2], "");
        r = strv_split_and_extend_full(&l, str2, ":", false, 0);
        assert_se(r == (int) strv_length(l));
        ASSERT_STREQ(l[3], "waldo");
        ASSERT_STREQ(l[4], "baz");
        ASSERT_STREQ(l[5], NULL);
}

TEST(strv_split_colon_pairs) {
        _cleanup_strv_free_ char **l = NULL;
        const char *str = "one:two three four:five six seven:eight\\:nine ten\\:eleven\\\\",
                   *str_inval="one:two three:four:five";
        int r;

        r = strv_split_colon_pairs(&l, str);
        assert_se(r == (int) strv_length(l));
        assert_se(r == 12);
        ASSERT_STREQ(l[0], "one");
        ASSERT_STREQ(l[1], "two");
        ASSERT_STREQ(l[2], "three");
        ASSERT_STREQ(l[3], "");
        ASSERT_STREQ(l[4], "four");
        ASSERT_STREQ(l[5], "five");
        ASSERT_STREQ(l[6], "six");
        ASSERT_STREQ(l[7], "");
        ASSERT_STREQ(l[8], "seven");
        ASSERT_STREQ(l[9], "eight:nine");
        ASSERT_STREQ(l[10], "ten:eleven\\");
        ASSERT_STREQ(l[11], "");
        ASSERT_STREQ(l[12], NULL);

        r = strv_split_colon_pairs(&l, str_inval);
        assert_se(r == -EINVAL);
}

TEST(strv_split_newlines) {
        unsigned i = 0;
        _cleanup_strv_free_ char **l = NULL;
        const char str[] = "one\ntwo\nthree";

        l = strv_split_newlines(str);
        assert_se(l);

        STRV_FOREACH(s, l)
                ASSERT_STREQ(*s, input_table_multiple[i++]);
}

TEST(strv_split_newlines_full) {
        const char str[] =
                "ID_VENDOR=QEMU\n"
                "ID_VENDOR_ENC=QEMU\\x20\\x20\\x20\\x20\n"
                "ID_MODEL_ENC=QEMU\\x20HARDDISK\\x20\\x20\\x20\n"
                "\n\n\n";
        _cleanup_strv_free_ char **l = NULL;

        assert_se(strv_split_newlines_full(&l, str, 0) == 3);
        assert_se(strv_equal(l, (char**) input_table_unescape));

        l = strv_free(l);

        assert_se(strv_split_newlines_full(&l, str, EXTRACT_RETAIN_ESCAPE) == 3);
        assert_se(strv_equal(l, (char**) input_table_retain_escape));
}

TEST(strv_overlap) {
        const char * const input_table[] = {
                "one",
                "two",
                "three",
                NULL
        };
        const char * const input_table_overlap[] = {
                "two",
                NULL
        };
        const char * const input_table_unique[] = {
                "four",
                "five",
                "six",
                NULL
        };

        assert_se(strv_overlap((char **)input_table, (char**)input_table_overlap));
        assert_se(!strv_overlap((char **)input_table, (char**)input_table_unique));
}

TEST(strv_sort) {
        const char* input_table[] = {
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                NULL
        };

        strv_sort((char **)input_table);

        ASSERT_STREQ(input_table[0], "CAPITAL LETTERS FIRST");
        ASSERT_STREQ(input_table[1], "apple");
        ASSERT_STREQ(input_table[2], "banana");
        ASSERT_STREQ(input_table[3], "citrus");
        ASSERT_STREQ(input_table[4], "durian");
}

TEST(strv_sort_uniq) {
        static const char* input_table[] = {
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                NULL
        };

        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL;

        ASSERT_NULL(strv_sort_uniq(a));

        ASSERT_NOT_NULL(a = strv_new(NULL));
        assert_se(strv_sort_uniq(a) == a);
        ASSERT_NULL(a[0]);
        a = strv_free(a);

        ASSERT_NOT_NULL(a = strv_new("a", "a", "a", "a", "a"));
        assert_se(strv_sort_uniq(a) == a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_NULL(a[1]);
        a = strv_free(a);

        ASSERT_NOT_NULL(a = strv_new("a", "a", "a", "a", "b"));
        assert_se(strv_sort_uniq(a) == a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL(a = strv_new("b", "a", "a", "a", "a"));
        assert_se(strv_sort_uniq(a) == a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL(a = strv_new("a", "a", "b", "a", "b"));
        assert_se(strv_sort_uniq(a) == a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL(a = strv_copy((char**) input_table));
        ASSERT_NOT_NULL(b = strv_copy((char**) input_table));
        ASSERT_NOT_NULL(c = strv_copy((char**) input_table));

        assert_se(strv_sort_uniq(a) == a);
        assert_se(strv_sort(strv_uniq(b)) == b);
        assert_se(strv_uniq(strv_sort(c)) == c);

        assert_se(strv_equal(a, b));
        assert_se(strv_equal(a, c));

        ASSERT_STREQ(a[0], "CAPITAL LETTERS FIRST");
        ASSERT_STREQ(a[1], "apple");
        ASSERT_STREQ(a[2], "banana");
        ASSERT_STREQ(a[3], "citrus");
        ASSERT_STREQ(a[4], "durian");
        ASSERT_NULL(a[5]);
}

TEST(strv_extend_strv_biconcat) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("without", "suffix");
        b = strv_new("with", "suffix");
        assert_se(a);
        assert_se(b);

        assert_se(strv_extend_strv_biconcat(&a, "prefix_", (const char* const*) b, "_suffix") >= 0);

        ASSERT_STREQ(a[0], "without");
        ASSERT_STREQ(a[1], "suffix");
        ASSERT_STREQ(a[2], "prefix_with_suffix");
        ASSERT_STREQ(a[3], "prefix_suffix_suffix");
}

TEST(strv_extend_strv_concat) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("without", "suffix");
        b = strv_new("with", "suffix");
        assert_se(a);
        assert_se(b);

        assert_se(strv_extend_strv_concat(&a, (const char* const*) b, "_suffix") >= 0);

        ASSERT_STREQ(a[0], "without");
        ASSERT_STREQ(a[1], "suffix");
        ASSERT_STREQ(a[2], "with_suffix");
        ASSERT_STREQ(a[3], "suffix_suffix");
}

TEST(strv_extend_strv) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **n = NULL;

        a = strv_new("abc", "def", "ghi");
        b = strv_new("jkl", "mno", "abc", "pqr");
        assert_se(a);
        assert_se(b);

        assert_se(strv_extend_strv(&a, b, true) == 3);

        ASSERT_STREQ(a[0], "abc");
        ASSERT_STREQ(a[1], "def");
        ASSERT_STREQ(a[2], "ghi");
        ASSERT_STREQ(a[3], "jkl");
        ASSERT_STREQ(a[4], "mno");
        ASSERT_STREQ(a[5], "pqr");
        assert_se(strv_length(a) == 6);

        assert_se(strv_extend_strv(&n, b, false) >= 0);
        ASSERT_STREQ(n[0], "jkl");
        ASSERT_STREQ(n[1], "mno");
        ASSERT_STREQ(n[2], "abc");
        ASSERT_STREQ(n[3], "pqr");
        assert_se(strv_length(n) == 4);
}

TEST(strv_extend_strv_consume) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **n = NULL;
        const char *s1, *s2, *s3;

        ASSERT_NOT_NULL(a = strv_new("abc", "def", "ghi"));
        ASSERT_NOT_NULL(b = strv_new("jkl", "mno", "abc", "pqr"));

        s1 = b[0];
        s2 = b[1];
        s3 = b[3];

        ASSERT_EQ(strv_extend_strv_consume(&a, TAKE_PTR(b), true), 3);

        assert_se(s1 == a[3]);
        assert_se(s2 == a[4]);
        assert_se(s3 == a[5]);

        ASSERT_STREQ(a[0], "abc");
        ASSERT_STREQ(a[1], "def");
        ASSERT_STREQ(a[2], "ghi");
        ASSERT_STREQ(a[3], "jkl");
        ASSERT_STREQ(a[4], "mno");
        ASSERT_STREQ(a[5], "pqr");
        ASSERT_EQ(strv_length(a), (size_t) 6);

        ASSERT_NOT_NULL(c = strv_new("jkl", "mno"));

        s1 = c[0];
        s2 = c[1];

        ASSERT_EQ(strv_extend_strv_consume(&n, TAKE_PTR(c), false), 2);

        assert_se(s1 == n[0]);
        assert_se(s2 == n[1]);

        ASSERT_STREQ(n[0], "jkl");
        ASSERT_STREQ(n[1], "mno");
        ASSERT_EQ(strv_length(n), (size_t) 2);
}

TEST(strv_extend_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = SIZE_MAX;

        a = strv_new("test", "test1");
        assert_se(a);

        assert_se(strv_extend_with_size(&a, &n, "test2") >= 0);
        assert_se(n == 3);
        assert_se(strv_extend_with_size(&a, &n, "test3") >= 0);
        assert_se(n == 4);

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2");
        ASSERT_STREQ(a[3], "test3");
        ASSERT_NULL(a[4]);
}

TEST(strv_extend) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("test", "test1");
        assert_se(a);
        assert_se(strv_extend(&a, "test2") >= 0);
        assert_se(strv_extend(&b, "test3") >= 0);

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2");
        ASSERT_STREQ(b[0], "test3");
}

TEST(strv_extendf) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("test", "test1");
        assert_se(a);
        assert_se(strv_extendf(&a, "test2 %s %d %s", "foo", 128, "bar") >= 0);
        assert_se(strv_extendf(&b, "test3 %s %s %d", "bar", "foo", 128) >= 0);

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2 foo 128 bar");
        ASSERT_STREQ(b[0], "test3 bar foo 128");
}

TEST(strv_foreach) {
        _cleanup_strv_free_ char **a;
        unsigned i = 0;

        a = strv_new("one", "two", "three");
        assert_se(a);

        STRV_FOREACH(check, a)
                ASSERT_STREQ(*check, input_table_multiple[i++]);
}

TEST(strv_foreach_backwards) {
        _cleanup_strv_free_ char **a;
        unsigned i = 2;

        a = strv_new("one", "two", "three");

        assert_se(a);

        STRV_FOREACH_BACKWARDS(check, a)
                ASSERT_STREQ(*check, input_table_multiple[i--]);

        STRV_FOREACH_BACKWARDS(check, (char**) NULL)
                assert_not_reached();

        STRV_FOREACH_BACKWARDS(check, STRV_MAKE_EMPTY)
                assert_not_reached();

        unsigned count = 0;
        STRV_FOREACH_BACKWARDS(check, STRV_MAKE("ONE"))
                count++;
        assert_se(count == 1);
}

TEST(strv_foreach_pair) {
        _cleanup_strv_free_ char **a = NULL;

        a = strv_new("pair_one",   "pair_one",
                     "pair_two",   "pair_two",
                     "pair_three", "pair_three");
        STRV_FOREACH_PAIR(x, y, a)
                ASSERT_STREQ(*x, *y);
}

static void test_strv_from_stdarg_alloca_one(char **l, const char *first, ...) {
        char **j;
        unsigned i;

        log_info("/* %s */", __func__);

        j = strv_from_stdarg_alloca(first);

        for (i = 0;; i++) {
                ASSERT_STREQ(l[i], j[i]);

                if (!l[i])
                        break;
        }
}

TEST(strv_from_stdarg_alloca) {
        test_strv_from_stdarg_alloca_one(STRV_MAKE("foo", "bar"), "foo", "bar", NULL);
        test_strv_from_stdarg_alloca_one(STRV_MAKE("foo"), "foo", NULL);
        test_strv_from_stdarg_alloca_one(STRV_MAKE_EMPTY, NULL);
}

TEST(strv_insert) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_insert(&a, 0, strdup("first")) == 0);
        ASSERT_STREQ(a[0], "first");
        assert_se(!a[1]);

        assert_se(strv_insert(&a, 0, NULL) == 0);
        ASSERT_STREQ(a[0], "first");
        assert_se(!a[1]);

        assert_se(strv_insert(&a, 1, strdup("two")) == 0);
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "two");
        assert_se(!a[2]);

        assert_se(strv_insert(&a, 4, strdup("tri")) == 0);
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "two");
        ASSERT_STREQ(a[2], "tri");
        assert_se(!a[3]);

        assert_se(strv_insert(&a, 1, strdup("duo")) == 0);
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "duo");
        ASSERT_STREQ(a[2], "two");
        ASSERT_STREQ(a[3], "tri");
        assert_se(!a[4]);
}

TEST(strv_push_prepend) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(a = strv_new("foo", "bar", "three"));

        assert_se(strv_push_prepend(&a, strdup("first")) >= 0);
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "foo");
        ASSERT_STREQ(a[2], "bar");
        ASSERT_STREQ(a[3], "three");
        assert_se(!a[4]);

        assert_se(strv_consume_prepend(&a, strdup("first2")) >= 0);
        ASSERT_STREQ(a[0], "first2");
        ASSERT_STREQ(a[1], "first");
        ASSERT_STREQ(a[2], "foo");
        ASSERT_STREQ(a[3], "bar");
        ASSERT_STREQ(a[4], "three");
        assert_se(!a[5]);
}

TEST(strv_push_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0;
        char *i, *j;

        assert_se(i = strdup("foo"));
        assert_se(strv_push_with_size(&a, &n, i) >= 0);
        assert_se(n == 1);

        assert_se(i = strdup("a"));
        assert_se(j = strdup("b"));
        assert_se(strv_push_with_size(&a, &n, i) >= 0);
        assert_se(n == 2);
        assert_se(strv_push_with_size(&a, &n, j) >= 0);
        assert_se(n == 3);

        ASSERT_STREQ(a[0], "foo");
        ASSERT_STREQ(a[1], "a");
        ASSERT_STREQ(a[2], "b");
        ASSERT_STREQ(a[3], NULL);

        assert_se(n = strv_length(a));
}

TEST(strv_push) {
        _cleanup_strv_free_ char **a = NULL;
        char *i, *j;

        assert_se(i = strdup("foo"));
        assert_se(strv_push(&a, i) >= 0);

        assert_se(i = strdup("a"));
        assert_se(j = strdup("b"));
        assert_se(strv_push_pair(&a, i, j) >= 0);

        ASSERT_STREQ(a[0], "foo");
        ASSERT_STREQ(a[1], "a");
        ASSERT_STREQ(a[2], "b");
        ASSERT_STREQ(a[3], NULL);
}

TEST(strv_compare) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_strv_free_ char **b = NULL;
        _cleanup_strv_free_ char **c = NULL;
        _cleanup_strv_free_ char **d = NULL;

        a = strv_new("one", "two", "three");
        assert_se(a);
        b = strv_new("one", "two", "three");
        assert_se(b);
        c = strv_new("one", "two", "three", "four");
        assert_se(c);
        d = strv_new(NULL);
        assert_se(d);

        assert_se(strv_compare(a, a) == 0);
        assert_se(strv_compare(a, b) == 0);
        assert_se(strv_compare(d, d) == 0);
        assert_se(strv_compare(d, NULL) == 0);
        assert_se(strv_compare(NULL, NULL) == 0);

        assert_se(strv_compare(a, c) < 0);
        assert_se(strv_compare(b, c) < 0);
        assert_se(strv_compare(b, d) == 1);
        assert_se(strv_compare(b, NULL) == 1);
}

TEST(strv_is_uniq) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = strv_new(NULL);
        assert_se(a);
        assert_se(strv_is_uniq(a));

        b = strv_new("foo");
        assert_se(b);
        assert_se(strv_is_uniq(b));

        c = strv_new("foo", "bar");
        assert_se(c);
        assert_se(strv_is_uniq(c));

        d = strv_new("foo", "bar", "waldo", "bar", "piep");
        assert_se(d);
        assert_se(!strv_is_uniq(d));
}

TEST(strv_reverse) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = strv_new(NULL);
        assert_se(a);

        strv_reverse(a);
        assert_se(strv_isempty(a));

        b = strv_new("foo");
        assert_se(b);
        strv_reverse(b);
        ASSERT_STREQ(b[0], "foo");
        ASSERT_STREQ(b[1], NULL);

        c = strv_new("foo", "bar");
        assert_se(c);
        strv_reverse(c);
        ASSERT_STREQ(c[0], "bar");
        ASSERT_STREQ(c[1], "foo");
        ASSERT_STREQ(c[2], NULL);

        d = strv_new("foo", "bar", "waldo");
        assert_se(d);
        strv_reverse(d);
        ASSERT_STREQ(d[0], "waldo");
        ASSERT_STREQ(d[1], "bar");
        ASSERT_STREQ(d[2], "foo");
        ASSERT_STREQ(d[3], NULL);
}

TEST(strv_shell_escape) {
        _cleanup_strv_free_ char **v = NULL;

        v = strv_new("foo:bar", "bar,baz", "wal\\do");
        assert_se(v);
        assert_se(strv_shell_escape(v, ",:"));
        ASSERT_STREQ(v[0], "foo\\:bar");
        ASSERT_STREQ(v[1], "bar\\,baz");
        ASSERT_STREQ(v[2], "wal\\\\do");
        ASSERT_STREQ(v[3], NULL);
}

static void test_strv_skip_one(char **a, size_t n, char **b) {
        a = strv_skip(a, n);
        assert_se(strv_equal(a, b));
}

TEST(strv_skip) {
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 0, STRV_MAKE("foo", "bar", "baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 1, STRV_MAKE("bar", "baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 2, STRV_MAKE("baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 3, STRV_MAKE(NULL));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 4, STRV_MAKE(NULL));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 55, STRV_MAKE(NULL));

        test_strv_skip_one(STRV_MAKE("quux"), 0, STRV_MAKE("quux"));
        test_strv_skip_one(STRV_MAKE("quux"), 1, STRV_MAKE(NULL));
        test_strv_skip_one(STRV_MAKE("quux"), 55, STRV_MAKE(NULL));

        test_strv_skip_one(STRV_MAKE(NULL), 0, STRV_MAKE(NULL));
        test_strv_skip_one(STRV_MAKE(NULL), 1, STRV_MAKE(NULL));
        test_strv_skip_one(STRV_MAKE(NULL), 55, STRV_MAKE(NULL));
}

TEST(strv_extend_n) {
        _cleanup_strv_free_ char **v = NULL;

        v = strv_new("foo", "bar");
        assert_se(v);

        assert_se(strv_extend_n(&v, "waldo", 3) >= 0);
        assert_se(strv_extend_n(&v, "piep", 2) >= 0);

        ASSERT_STREQ(v[0], "foo");
        ASSERT_STREQ(v[1], "bar");
        ASSERT_STREQ(v[2], "waldo");
        ASSERT_STREQ(v[3], "waldo");
        ASSERT_STREQ(v[4], "waldo");
        ASSERT_STREQ(v[5], "piep");
        ASSERT_STREQ(v[6], "piep");
        ASSERT_NULL(v[7]);

        v = strv_free(v);

        assert_se(strv_extend_n(&v, "foo", 1) >= 0);
        assert_se(strv_extend_n(&v, "bar", 0) >= 0);

        ASSERT_STREQ(v[0], "foo");
        ASSERT_NULL(v[1]);
}

TEST(foreach_string) {
        const char * const t[] = {
                "foo",
                "bar",
                "waldo",
                NULL
        };

        unsigned i = 0;
        FOREACH_STRING(x, "foo", "bar", "waldo")
                ASSERT_STREQ(t[i++], x);
        assert_se(i == 3);

        FOREACH_STRING(x, "zzz")
                ASSERT_STREQ(x, "zzz");
}

TEST(strv_fnmatch) {
        _cleanup_strv_free_ char **v = NULL;
        size_t pos;

        assert_se(!strv_fnmatch(STRV_MAKE_EMPTY, "a"));

        v = strv_new("xxx", "*\\*", "yyy");
        assert_se(!strv_fnmatch_full(v, "\\", 0, NULL));
        assert_se(strv_fnmatch_full(v, "\\", FNM_NOESCAPE, &pos));
        assert_se(pos == 1);
}

TEST(strv_extend_join) {
        _cleanup_strv_free_ char **v = NULL;

        assert_se(strv_extend_assignment(&v, "MESSAGE", "ABC") >= 0);
        assert_se(strv_extend_assignment(&v, "ABC", "QER") >= 0);
        assert_se(strv_extend_assignment(&v, "MISSING", NULL) >= 0);

        assert_se(strv_length(v) == 2);
        ASSERT_STREQ(v[0], "MESSAGE=ABC");
        ASSERT_STREQ(v[1], "ABC=QER");
}

TEST(strv_copy_n) {
        char **x = STRV_MAKE("a", "b", "c", "d", "e");
        _cleanup_strv_free_ char **l = NULL;

        l = strv_copy_n(x, 0);
        assert_se(strv_equal(l, NULL));
        strv_free(l);

        l = strv_copy_n(x, 0);
        assert_se(strv_equal(l, (char**) { NULL }));
        strv_free(l);

        l = strv_copy_n(x, 1);
        assert_se(strv_equal(l, STRV_MAKE("a")));
        strv_free(l);

        l = strv_copy_n(x, 2);
        assert_se(strv_equal(l, STRV_MAKE("a", "b")));
        strv_free(l);

        l = strv_copy_n(x, 3);
        assert_se(strv_equal(l, STRV_MAKE("a", "b", "c")));
        strv_free(l);

        l = strv_copy_n(x, 4);
        assert_se(strv_equal(l, STRV_MAKE("a", "b", "c", "d")));
        strv_free(l);

        l = strv_copy_n(x, 5);
        assert_se(strv_equal(l, STRV_MAKE("a", "b", "c", "d", "e")));
        strv_free(l);

        l = strv_copy_n(x, 6);
        assert_se(strv_equal(l, STRV_MAKE("a", "b", "c", "d", "e")));
        strv_free(l);

        l = strv_copy_n(x, SIZE_MAX);
        assert_se(strv_equal(l, STRV_MAKE("a", "b", "c", "d", "e")));
}

TEST(strv_find_first_field) {
        char **haystack = STRV_MAKE("a", "b", "c", "d", "e", "f", "g", "h", "i", "j");

        ASSERT_NULL(strv_find_first_field(NULL, NULL));
        ASSERT_NULL(strv_find_first_field(NULL, haystack));
        ASSERT_NULL(strv_find_first_field(STRV_MAKE("k", "l", "m", "d", "b"), NULL));
        ASSERT_NULL(strv_find_first_field(STRV_MAKE("k", "l", "m", "d", "b"), haystack));
        ASSERT_STREQ(strv_find_first_field(STRV_MAKE("k", "l", "m", "d", "a", "c"), haystack), "b");
        ASSERT_STREQ(strv_find_first_field(STRV_MAKE("k", "l", "m", "d", "c", "a"), haystack), "d");
        ASSERT_STREQ(strv_find_first_field(STRV_MAKE("i", "k", "l", "m", "d", "c", "a", "b"), haystack), "j");
}

TEST(endswith_strv) {
        ASSERT_STREQ(endswith_strv("waldo", STRV_MAKE("xxx", "yyy", "ldo", "zzz")), "ldo");
        ASSERT_STREQ(endswith_strv("waldo", STRV_MAKE("xxx", "yyy", "zzz")), NULL);
        ASSERT_STREQ(endswith_strv("waldo", STRV_MAKE("waldo")), "waldo");
        ASSERT_STREQ(endswith_strv("waldo", STRV_MAKE("w", "o", "ldo")), "o");
        ASSERT_STREQ(endswith_strv("waldo", STRV_MAKE("knurz", "", "waldo")), "");
}

TEST(strv_extend_many) {
        _cleanup_strv_free_ char **l = NULL;

        assert_se(strv_extend_many(&l, NULL) >= 0);
        assert_se(strv_isempty(l));

        assert_se(strv_extend_many(&l, NULL, NULL, NULL) >= 0);
        assert_se(strv_isempty(l));

        assert_se(strv_extend_many(&l, "foo") >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo")));

        assert_se(strv_extend_many(&l, NULL, "bar", NULL) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo", "bar")));

        assert_se(strv_extend_many(&l, "waldo", "quux") >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo", "bar", "waldo", "quux")));

        assert_se(strv_extend_many(&l, "1", "2", "3", "4") >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo", "bar", "waldo", "quux", "1", "2", "3", "4")));

        assert_se(strv_extend_many(&l, "yes", NULL, "no") >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo", "bar", "waldo", "quux", "1", "2", "3", "4", "yes", "no")));
}

TEST(strv_rebreak_lines) {
        _cleanup_strv_free_ char **l = NULL;

        assert_se(strv_rebreak_lines(NULL, SIZE_MAX, &l) >= 0);
        assert_se(strv_equal(l, NULL));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE(""), SIZE_MAX, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("", ""), SIZE_MAX, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("", "")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("foo"), SIZE_MAX, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("foo", "bar"), SIZE_MAX, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("foo", "bar")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("Foo fOo foO FOo", "bar Bar bAr baR BAr"), 10, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("Foo fOo", "foO FOo", "bar Bar", "bAr baR", "BAr")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("           foo               ",
                                               "             foo bar               waldo quux         "),
                                     10, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("           foo",
                                          "             foo",
                                          "bar",
                                          "waldo quux")));
        l = strv_free(l);

        assert_se(strv_rebreak_lines(STRV_MAKE("            ",
                                               "\tfoo bar\t",
                                               "FOO\tBAR"),
                                     10, &l) >= 0);
        assert_se(strv_equal(l, STRV_MAKE("",
                                          "\tfoo",
                                          "bar",
                                          "FOO",
                                          "BAR")));
        l = strv_free(l);

        /* Now make sure that breaking the lines a 2nd time does not modify the output anymore */
        for (size_t i = 1; i < 100; i++) {
                _cleanup_strv_free_ char **a = NULL, **b = NULL;

                assert_se(strv_rebreak_lines(STRV_MAKE("foobar waldo waldo quux piep\tschnurz    pimm"), i, &a) >= 0);
                assert_se(strv_rebreak_lines(a, i, &b) >= 0);

                assert_se(strv_equal(a, b));
        }
}

TEST(strv_find_closest) {
        char **l = STRV_MAKE("aaa", "aaaa", "bbb", "ccc");

        /* prefix match */
        ASSERT_STREQ(strv_find_closest(l, "a"),    "aaa");
        ASSERT_STREQ(strv_find_closest(l, "aa"),   "aaa");
        ASSERT_STREQ(strv_find_closest(l, "aaa"),  "aaa");
        ASSERT_STREQ(strv_find_closest(l, "aaaa"), "aaaa");
        ASSERT_STREQ(strv_find_closest(l, "b"),    "bbb");
        ASSERT_STREQ(strv_find_closest(l, "bb"),   "bbb");
        ASSERT_STREQ(strv_find_closest(l, "bbb"),  "bbb");
        ASSERT_STREQ(strv_find_closest(l, "c"),    "ccc");
        ASSERT_STREQ(strv_find_closest(l, "cc"),   "ccc");
        ASSERT_STREQ(strv_find_closest(l, "ccc"),  "ccc");

        /* levenshtein match */
        ASSERT_STREQ(strv_find_closest(l, "aab"),  "aaa");
        ASSERT_STREQ(strv_find_closest(l, "abb"),  "bbb");
        ASSERT_STREQ(strv_find_closest(l, "cbc"),  "ccc");
        ASSERT_STREQ(strv_find_closest(l, "aax"),  "aaa");
        ASSERT_STREQ(strv_find_closest(l, "bbbb"), "bbb");
        ASSERT_STREQ(strv_find_closest(l, "cbbb"), "bbb");
        ASSERT_STREQ(strv_find_closest(l, "bbbx"), "bbb");

        ASSERT_NULL(strv_find_closest(l, "sfajosajfosdjaofjdsaf"));
}

TEST(strv_equal_ignore_order) {

        ASSERT_TRUE(strv_equal_ignore_order(NULL, NULL));
        ASSERT_TRUE(strv_equal_ignore_order(NULL, STRV_MAKE(NULL)));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE(NULL), NULL));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE(NULL), STRV_MAKE(NULL)));

        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("foo"), NULL));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("foo"), STRV_MAKE(NULL)));
        ASSERT_FALSE(strv_equal_ignore_order(NULL, STRV_MAKE("foo")));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE(NULL), STRV_MAKE("foo")));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE("foo"), STRV_MAKE("foo")));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("foo"), STRV_MAKE("foo", "bar")));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("foo", "bar"), STRV_MAKE("foo")));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE("foo", "bar"), STRV_MAKE("foo", "bar")));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE("bar", "foo"), STRV_MAKE("foo", "bar")));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("bar", "foo"), STRV_MAKE("foo", "bar", "quux")));
        ASSERT_FALSE(strv_equal_ignore_order(STRV_MAKE("bar", "foo", "quux"), STRV_MAKE("foo", "bar")));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE("bar", "foo", "quux"), STRV_MAKE("quux", "foo", "bar")));
        ASSERT_TRUE(strv_equal_ignore_order(STRV_MAKE("bar", "foo"), STRV_MAKE("bar", "foo", "bar", "foo", "foo")));
}

DEFINE_TEST_MAIN(LOG_INFO);
