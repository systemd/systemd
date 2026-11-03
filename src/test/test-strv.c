/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(str_in_set) {
        ASSERT_TRUE(STR_IN_SET("x", "x", "y", "z"));
        ASSERT_FALSE(STR_IN_SET("X", "x", "y", "z"));
        ASSERT_FALSE(STR_IN_SET("", "x", "y", "z"));
        ASSERT_TRUE(STR_IN_SET("x", "w", "x"));
}

TEST(strptr_in_set) {
        ASSERT_TRUE(STRPTR_IN_SET("x", "x", "y", "z"));
        ASSERT_FALSE(STRPTR_IN_SET("X", "x", "y", "z"));
        ASSERT_FALSE(STRPTR_IN_SET("", "x", "y", "z"));
        ASSERT_TRUE(STRPTR_IN_SET("x", "w", "x"));

        ASSERT_FALSE(STRPTR_IN_SET(NULL, "x", "y", "z"));
        ASSERT_FALSE(STRPTR_IN_SET(NULL, ""));
        /* strv cannot contain a null, hence the result below */
        ASSERT_FALSE(STRPTR_IN_SET(NULL, NULL));
}

TEST(startswith_set) {
        ASSERT_FALSE(STARTSWITH_SET("foo", "bar", "baz", "waldo"));
        ASSERT_FALSE(STARTSWITH_SET("foo", "bar"));

        ASSERT_TRUE(STARTSWITH_SET("abc", "a", "ab", "abc"));
        ASSERT_TRUE(STARTSWITH_SET("abc", "ax", "ab", "abc"));
        ASSERT_TRUE(STARTSWITH_SET("abc", "ax", "abx", "abc"));
        ASSERT_FALSE(STARTSWITH_SET("abc", "ax", "abx", "abcx"));

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
        ASSERT_NOT_NULL(strv_find((char **)input_table_multiple, "three"));
        ASSERT_NULL(strv_find((char **)input_table_multiple, "four"));
}

TEST(strv_find_prefix) {
        ASSERT_NOT_NULL(strv_find_prefix((char **)input_table_multiple, "o"));
        ASSERT_NOT_NULL(strv_find_prefix((char **)input_table_multiple, "one"));
        ASSERT_NOT_NULL(strv_find_prefix((char **)input_table_multiple, ""));
        ASSERT_NULL(strv_find_prefix((char **)input_table_multiple, "xxx"));
        ASSERT_NULL(strv_find_prefix((char **)input_table_multiple, "onee"));
}

TEST(strv_find_startswith) {
        char *r;

        r = strv_find_startswith((char **)input_table_multiple, "o");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "ne");

        r = strv_find_startswith((char **)input_table_multiple, "one");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "");

        r = strv_find_startswith((char **)input_table_multiple, "");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "one");

        ASSERT_NULL(strv_find_startswith((char **)input_table_multiple, "xxx"));
        ASSERT_NULL(strv_find_startswith((char **)input_table_multiple, "onee"));
}

TEST(strv_join) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(strv_join((char **)input_table_multiple, ", "));
        ASSERT_STREQ(p, "one, two, three");

        _cleanup_free_ char *q = ASSERT_NOT_NULL(strv_join((char **)input_table_multiple, ";"));
        ASSERT_STREQ(q, "one;two;three");

        _cleanup_free_ char *r =
                ASSERT_NOT_NULL(strv_join((char **)input_table_multiple, /* separator= */ NULL));
        ASSERT_STREQ(r, "one two three");

        _cleanup_free_ char *s = ASSERT_NOT_NULL(strv_join(STRV_MAKE("1", "2", "3,3"), ","));
        ASSERT_STREQ(s, "1,2,3,3");

        _cleanup_free_ char *t = ASSERT_NOT_NULL(strv_join((char **)input_table_one, ", "));
        ASSERT_STREQ(t, "one");

        _cleanup_free_ char *u = ASSERT_NOT_NULL(strv_join((char **)input_table_none, ", "));
        ASSERT_STREQ(u, "");

        _cleanup_free_ char *v = ASSERT_NOT_NULL(strv_join((char **)input_table_two_empties, ", "));
        ASSERT_STREQ(v, ", ");

        _cleanup_free_ char *w = ASSERT_NOT_NULL(strv_join((char **)input_table_one_empty, ", "));
        ASSERT_STREQ(w, "");
}

TEST(strv_join_full) {
        _cleanup_free_ char *p = ASSERT_NOT_NULL(strv_join_full((char **)input_table_multiple, ", ", "foo"));
        ASSERT_STREQ(p, "fooone, footwo, foothree");

        _cleanup_free_ char *q = ASSERT_NOT_NULL(strv_join_full((char **)input_table_multiple, ";", "foo"));
        ASSERT_STREQ(q, "fooone;footwo;foothree");

        _cleanup_free_ char *u =
                ASSERT_NOT_NULL(strv_join_full((char **)input_table_multiple, /* separator= */ NULL, "foo"));
        ASSERT_STREQ(u, "fooone footwo foothree");

        _cleanup_free_ char *v = ASSERT_NOT_NULL(strv_join_full((char **)input_table_one, ", ", "foo"));
        ASSERT_STREQ(v, "fooone");

        _cleanup_free_ char *w = ASSERT_NOT_NULL(strv_join_full((char **)input_table_none, ", ", "foo"));
        ASSERT_STREQ(w, "");

        _cleanup_free_ char *x =
                ASSERT_NOT_NULL(strv_join_full((char **)input_table_two_empties, ", ", "foo"));
        ASSERT_STREQ(x, "foo, foo");

        _cleanup_free_ char *y =
                ASSERT_NOT_NULL(strv_join_full((char **)input_table_one_empty, ", ", "foo"));
        ASSERT_STREQ(y, "foo");
}

static void test_strv_unquote_one(const char *quoted, char **list) {
        _cleanup_strv_free_ char **s = NULL;
        _cleanup_free_ char *j = NULL;
        unsigned i = 0;
        int r;

        log_info("/* %s */", __func__);

        r = strv_split_full(&s, quoted, WHITESPACE, EXTRACT_UNQUOTE);
        ASSERT_EQ(r, (int) strv_length(list));
        ASSERT_NOT_NULL(s);
        j = ASSERT_NOT_NULL(strv_join(s, " | "));
        puts(j);

        STRV_FOREACH(t, s)
                ASSERT_STREQ(list[i++], *t);

        ASSERT_NULL(list[i]);
}

TEST(strv_unquote) {
        test_strv_unquote_one("    foo=bar     \"waldo\"    zzz    ", STRV_MAKE("foo=bar", "waldo", "zzz"));
        test_strv_unquote_one("", STRV_EMPTY);
        test_strv_unquote_one(" ", STRV_EMPTY);
        test_strv_unquote_one("   ", STRV_EMPTY);
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
        ASSERT_ERROR(r, EINVAL);
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

        l = ASSERT_NOT_NULL(strv_split(str, ","));
        ASSERT_STRV_EQ(l, (char**) input_table_multiple);

        strv_free_erase(l);

        l = ASSERT_NOT_NULL(strv_split("    one    two\t three", WHITESPACE));
        ASSERT_STRV_EQ(l, (char**) input_table_multiple);

        strv_free_erase(l);

        /* Setting NULL for separator is equivalent to WHITESPACE */
        l = ASSERT_NOT_NULL(strv_split("    one    two\t three", /* separators= */ NULL));
        ASSERT_STRV_EQ(l, (char**) input_table_multiple);

        strv_free_erase(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    one    two\t three", /* separators= */ NULL, /* flags= */ 0), 3);
        ASSERT_STRV_EQ(l, (char**) input_table_multiple);

        strv_free_erase(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five'", /* separators= */ NULL, EXTRACT_UNQUOTE), 3);
        ASSERT_STRV_EQ(l, (char**) input_table_quoted);

        l = strv_free_erase(l);

        /* missing last quote causes extraction to fail. */
        ASSERT_ERROR(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five", /* separators= */ NULL, EXTRACT_UNQUOTE), EINVAL);
        ASSERT_NULL(l);

        /* missing last quote, but the last element is _not_ ignored with EXTRACT_RELAX. */
        ASSERT_OK_EQ(strv_split_full(&l, "    'one'  \"  two\t three \" ' four  five", /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX), 3);
        ASSERT_STRV_EQ(l, (char**) input_table_quoted);

        l = strv_free_erase(l);

        /* missing separator between items */
        ASSERT_OK_EQ(strv_split_full(&l, "    'one'  \"  two\t three \"' four  five'", /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX), 2);
        ASSERT_STRV_EQ(l, (char**) input_table_quoted_joined);

        l = strv_free_erase(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    'one'  \"  two\t three \"' four  five", /* separators= */ NULL,
                                     EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_UNESCAPE_RELAX), 2);
        ASSERT_STRV_EQ(l, (char**) input_table_quoted_joined);

        l = strv_free_erase(l);

        ASSERT_OK_EQ(strv_split_full(&l, "\\", /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_UNESCAPE_RELAX), 1);
        ASSERT_STRV_EQ(l, STRV_MAKE("\\"));

        l = strv_free_erase(l);

        ASSERT_NOT_NULL(l = strv_split("\\", /* separators= */ NULL));
        ASSERT_STRV_EQ(l, STRV_MAKE("\\"));

        l = strv_free_erase(l);

        ASSERT_NOT_NULL(l = strv_split("aa\\ bb\\", /* separators= */ NULL));
        ASSERT_STRV_EQ(l, STRV_MAKE("aa\\", "bb\\"));

        l = strv_free_erase(l);

        ASSERT_NOT_NULL(l = strv_split("aa\" bb'", /* separators= */ NULL));
        ASSERT_STRV_EQ(l, STRV_MAKE("aa\"", "bb'"));
}

TEST(strv_split_empty) {
        _cleanup_strv_free_ char **l = NULL;

        l = ASSERT_NOT_NULL(strv_split("", WHITESPACE));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_NOT_NULL(l = strv_split("", /* separators= */ NULL));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "", /* separators= */ NULL, /* flags= */ 0), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "", /* separators= */ NULL, EXTRACT_UNQUOTE), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "", WHITESPACE, EXTRACT_UNQUOTE), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "", WHITESPACE, EXTRACT_UNQUOTE | EXTRACT_RELAX), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        strv_free(l);

        l = ASSERT_NOT_NULL(strv_split("    ", WHITESPACE));
        ASSERT_TRUE(strv_isempty(l));
        strv_free(l);

        l = ASSERT_NOT_NULL(strv_split("    ", /* separators= */ NULL));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    ", /* separators= */ NULL, /* flags= */ 0), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    ", WHITESPACE, EXTRACT_UNQUOTE), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    ", /* separators= */ NULL, EXTRACT_UNQUOTE), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_full(&l, "    ", /* separators= */ NULL,
                                     EXTRACT_UNQUOTE | EXTRACT_RELAX), 0);
        ASSERT_NOT_NULL(l);
        ASSERT_TRUE(strv_isempty(l));
}

TEST(strv_split_full) {
        _cleanup_strv_free_ char **l = NULL;
        const char *str = ":foo\\:bar::waldo:";
        int r;

        r = strv_split_full(&l, str, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        ASSERT_EQ(r, (int) strv_length(l));
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

        r = strv_split_and_extend(&l, "", ":", /* filter_duplicates= */ false);
        ASSERT_EQ(r, (int) strv_length(l));
        r = strv_split_and_extend_full(&l, str1, ":", /* filter_duplicates= */ false, EXTRACT_DONT_COALESCE_SEPARATORS);
        ASSERT_EQ(r, (int) strv_length(l));
        ASSERT_STREQ(l[0], "");
        ASSERT_STREQ(l[1], "foo:bar");
        ASSERT_STREQ(l[2], "");
        r = strv_split_and_extend_full(&l, str2, ":", /* filter_duplicates= */ false, /* flags= */ 0);
        ASSERT_EQ(r, (int) strv_length(l));
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
        ASSERT_EQ(r, (int) strv_length(l));
        ASSERT_OK_EQ(r, 12);
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

        ASSERT_ERROR(strv_split_colon_pairs(&l, str_inval), EINVAL);
}

TEST(strv_split_newlines) {
        unsigned i = 0;
        _cleanup_strv_free_ char **l = NULL;
        const char str[] = "one\ntwo\nthree";

        l = ASSERT_NOT_NULL(strv_split_newlines(str));

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

        ASSERT_OK_EQ(strv_split_newlines_full(&l, str, /* flags= */ 0), 3);
        ASSERT_STRV_EQ(l, (char**) input_table_unescape);

        l = strv_free(l);

        ASSERT_OK_EQ(strv_split_newlines_full(&l, str, EXTRACT_RETAIN_ESCAPE), 3);
        ASSERT_STRV_EQ(l, (char**) input_table_retain_escape);
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

        ASSERT_TRUE(strv_overlap((char **)input_table, (char**)input_table_overlap));
        ASSERT_FALSE(strv_overlap((char **)input_table, (char**)input_table_unique));
}

TEST(strv_remove_strv) {
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(strv_extend_strv(&l, STRV_MAKE("one", "two", "three", "four"), /* filter_duplicates= */ false));

        ASSERT_PTR_EQ(strv_remove_strv(l, STRV_MAKE("two", "four")), l);
        ASSERT_STRV_EQ(l, STRV_MAKE("one", "three"));

        /* Removing entries not present is a no-op. */
        ASSERT_PTR_EQ(strv_remove_strv(l, STRV_MAKE("nope")), l);
        ASSERT_STRV_EQ(l, STRV_MAKE("one", "three"));

        /* Empty removal list leaves the list untouched. */
        ASSERT_PTR_EQ(strv_remove_strv(l, STRV_EMPTY), l);
        ASSERT_STRV_EQ(l, STRV_MAKE("one", "three"));

        /* Removing from an empty/NULL list is fine. */
        ASSERT_NULL(strv_remove_strv(NULL, STRV_MAKE("one")));
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

        ASSERT_NOT_NULL((a = strv_new(NULL)));
        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_NULL(a[0]);
        a = strv_free(a);

        ASSERT_NOT_NULL((a = strv_new("a", "a", "a", "a", "a")));
        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_NULL(a[1]);
        a = strv_free(a);

        ASSERT_NOT_NULL((a = strv_new("a", "a", "a", "a", "b")));
        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL((a = strv_new("b", "a", "a", "a", "a")));
        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL((a = strv_new("a", "a", "b", "a", "b")));
        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_STREQ(a[0], "a");
        ASSERT_STREQ(a[1], "b");
        ASSERT_NULL(a[2]);
        a = strv_free(a);

        ASSERT_NOT_NULL((a = strv_copy((char**) input_table)));
        ASSERT_NOT_NULL((b = strv_copy((char**) input_table)));
        ASSERT_NOT_NULL((c = strv_copy((char**) input_table)));

        ASSERT_PTR_EQ(strv_sort_uniq(a), a);
        ASSERT_PTR_EQ(strv_sort(strv_uniq(b)), b);
        ASSERT_PTR_EQ(strv_uniq(strv_sort(c)), c);

        ASSERT_STRV_EQ(a, b);
        ASSERT_STRV_EQ(a, c);

        ASSERT_STREQ(a[0], "CAPITAL LETTERS FIRST");
        ASSERT_STREQ(a[1], "apple");
        ASSERT_STREQ(a[2], "banana");
        ASSERT_STREQ(a[3], "citrus");
        ASSERT_STREQ(a[4], "durian");
        ASSERT_NULL(a[5]);
}

static int str_compare_reverse(char * const *a, char * const *b) {
        return -strcmp(*a, *b);
}

TEST(strv_sort_uniq_full) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_NULL(strv_sort_uniq_full(a, str_compare_reverse));

        ASSERT_NOT_NULL((a = strv_new("b", "a", "c", "a", "b", "a")));
        ASSERT_PTR_EQ(strv_sort_uniq_full(a, str_compare_reverse), a);
        ASSERT_STREQ(a[0], "c");
        ASSERT_STREQ(a[1], "b");
        ASSERT_STREQ(a[2], "a");
        ASSERT_NULL(a[3]);
}

TEST(strv_extend_strv_biconcat) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("without", "suffix");
        b = strv_new("with", "suffix");
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        ASSERT_OK(strv_extend_strv_biconcat(&a, "prefix_", (const char* const*) b, "_suffix"));

        ASSERT_STREQ(a[0], "without");
        ASSERT_STREQ(a[1], "suffix");
        ASSERT_STREQ(a[2], "prefix_with_suffix");
        ASSERT_STREQ(a[3], "prefix_suffix_suffix");
}

TEST(strv_extend_strv_concat) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("without", "suffix");
        b = strv_new("with", "suffix");
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        ASSERT_OK(strv_extend_strv_concat(&a, (const char* const*) b, "_suffix"));

        ASSERT_STREQ(a[0], "without");
        ASSERT_STREQ(a[1], "suffix");
        ASSERT_STREQ(a[2], "with_suffix");
        ASSERT_STREQ(a[3], "suffix_suffix");
}

TEST(strv_extend_strv) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **n = NULL;

        a = strv_new("abc", "def", "ghi");
        b = strv_new("jkl", "mno", "abc", "pqr");
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        ASSERT_OK_EQ(strv_extend_strv(&a, b, /* filter_duplicates= */ true), 3);

        ASSERT_STREQ(a[0], "abc");
        ASSERT_STREQ(a[1], "def");
        ASSERT_STREQ(a[2], "ghi");
        ASSERT_STREQ(a[3], "jkl");
        ASSERT_STREQ(a[4], "mno");
        ASSERT_STREQ(a[5], "pqr");
        ASSERT_EQ(strv_length(a), 6U);

        ASSERT_OK(strv_extend_strv(&n, b, /* filter_duplicates= */ false));
        ASSERT_STREQ(n[0], "jkl");
        ASSERT_STREQ(n[1], "mno");
        ASSERT_STREQ(n[2], "abc");
        ASSERT_STREQ(n[3], "pqr");
        ASSERT_EQ(strv_length(n), 4U);
}

TEST(strv_extend_strv_consume) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **n = NULL;
        const char *s1, *s2, *s3;

        ASSERT_NOT_NULL((a = strv_new("abc", "def", "ghi")));
        ASSERT_NOT_NULL((b = strv_new("jkl", "mno", "abc", "pqr")));

        s1 = b[0];
        s2 = b[1];
        s3 = b[3];

        ASSERT_EQ(strv_extend_strv_consume(&a, TAKE_PTR(b), /* filter_duplicates= */ true), 3);

        ASSERT_PTR_EQ(s1, a[3]);
        ASSERT_PTR_EQ(s2, a[4]);
        ASSERT_PTR_EQ(s3, a[5]);

        ASSERT_STREQ(a[0], "abc");
        ASSERT_STREQ(a[1], "def");
        ASSERT_STREQ(a[2], "ghi");
        ASSERT_STREQ(a[3], "jkl");
        ASSERT_STREQ(a[4], "mno");
        ASSERT_STREQ(a[5], "pqr");
        ASSERT_EQ(strv_length(a), (size_t) 6);

        ASSERT_NOT_NULL((c = strv_new("jkl", "mno")));

        s1 = c[0];
        s2 = c[1];

        ASSERT_EQ(strv_extend_strv_consume(&n, TAKE_PTR(c), /* filter_duplicates= */ false), 2);

        ASSERT_PTR_EQ(s1, n[0]);
        ASSERT_PTR_EQ(s2, n[1]);

        ASSERT_STREQ(n[0], "jkl");
        ASSERT_STREQ(n[1], "mno");
        ASSERT_EQ(strv_length(n), (size_t) 2);
}

TEST(strv_extend_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = SIZE_MAX;

        a = ASSERT_NOT_NULL(strv_new("test", "test1"));

        ASSERT_OK(strv_extend_with_size(&a, &n, "test2"));
        ASSERT_EQ(n, 3U);
        ASSERT_OK(strv_extend_with_size(&a, &n, "test3"));
        ASSERT_EQ(n, 4U);

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2");
        ASSERT_STREQ(a[3], "test3");
        ASSERT_NULL(a[4]);
}

TEST(strv_extend) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = ASSERT_NOT_NULL(strv_new("test", "test1"));
        ASSERT_OK(strv_extend(&a, "test2"));
        ASSERT_OK(strv_extend(&b, "test3"));

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2");
        ASSERT_STREQ(b[0], "test3");
}

TEST(strv_extendf) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = ASSERT_NOT_NULL(strv_new("test", "test1"));
        ASSERT_OK(strv_extendf(&a, "test2 %s %d %s", "foo", 128, "bar"));
        ASSERT_OK(strv_extendf(&b, "test3 %s %s %d", "bar", "foo", 128));

        ASSERT_STREQ(a[0], "test");
        ASSERT_STREQ(a[1], "test1");
        ASSERT_STREQ(a[2], "test2 foo 128 bar");
        ASSERT_STREQ(b[0], "test3 bar foo 128");
}

TEST(strv_extendf_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0;

        ASSERT_OK(strv_extendf_with_size(&a, &n, "test2 %s %d %s", "foo", 128, "bar"));
        ASSERT_OK(strv_extendf_with_size(&a, &n, "test3 %s %s %d", "bar", "foo", 128));

        ASSERT_EQ(n, 2u);
        ASSERT_EQ(strv_length(a), n);
        ASSERT_STREQ(a[0], "test2 foo 128 bar");
        ASSERT_STREQ(a[1], "test3 bar foo 128");
}

TEST(strv_extend_joined) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK(strv_extend_joined(&a, "hoge"));
        ASSERT_OK(strv_extend_joined(&a, "aaa", "bbb", "ccc"));

        ASSERT_EQ(strv_length(a), 2u);
        ASSERT_STREQ(a[0], "hoge");
        ASSERT_STREQ(a[1], "aaabbbccc");
}

TEST(strv_extend_joined_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0;

        ASSERT_OK(strv_extend_joined_with_size(&a, &n, "hoge"));
        ASSERT_OK(strv_extend_joined_with_size(&a, &n, "aaa", "bbb", "ccc"));

        ASSERT_EQ(n, 2u);
        ASSERT_EQ(strv_length(a), n);
        ASSERT_STREQ(a[0], "hoge");
        ASSERT_STREQ(a[1], "aaabbbccc");
}

TEST(strv_foreach) {
        _cleanup_strv_free_ char **a;
        unsigned i = 0;

        a = ASSERT_NOT_NULL(strv_new("one", "two", "three"));

        STRV_FOREACH(check, a)
                ASSERT_STREQ(*check, input_table_multiple[i++]);
}

TEST(strv_foreach_backwards) {
        _cleanup_strv_free_ char **a;
        unsigned i = 3;

        a = strv_new("one", "two", "three");

        ASSERT_NOT_NULL(a);

        STRV_FOREACH_BACKWARDS(check, a)
                ASSERT_STREQ(*check, input_table_multiple[--i]);

        STRV_FOREACH_BACKWARDS(check, (char**) NULL)
                assert_not_reached();

        STRV_FOREACH_BACKWARDS(check, STRV_EMPTY)
                assert_not_reached();

        unsigned count = 0;
        STRV_FOREACH_BACKWARDS(check, STRV_MAKE("ONE"))
                count++;
        ASSERT_EQ(count, 1U);
}

TEST(strv_foreach_pair) {
        _cleanup_strv_free_ char **a = NULL;

        a = strv_new("pair_one",   "pair_one",
                     "pair_two",   "pair_two",
                     "pair_three", "pair_three");
        STRV_FOREACH_PAIR(x, y, a)
                ASSERT_STREQ(*x, *y);
}

TEST(strv_insert) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK_ZERO(strv_insert(&a, /* position= */ 0, strdup("first")));
        ASSERT_STREQ(a[0], "first");
        ASSERT_NULL(a[1]);

        ASSERT_OK_ZERO(strv_insert(&a, /* position= */ 0, /* value= */ NULL));
        ASSERT_STREQ(a[0], "first");
        ASSERT_NULL(a[1]);

        ASSERT_OK_ZERO(strv_insert(&a, 1, strdup("two")));
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "two");
        ASSERT_NULL(a[2]);

        ASSERT_OK_ZERO(strv_insert(&a, 4, strdup("tri")));
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "two");
        ASSERT_STREQ(a[2], "tri");
        ASSERT_NULL(a[3]);

        ASSERT_OK_ZERO(strv_insert(&a, 1, strdup("duo")));
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "duo");
        ASSERT_STREQ(a[2], "two");
        ASSERT_STREQ(a[3], "tri");
        ASSERT_NULL(a[4]);
}

TEST(strv_push_prepend) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_NOT_NULL(a = strv_new("foo", "bar", "three"));

        ASSERT_OK(strv_push_prepend(&a, strdup("first")));
        ASSERT_STREQ(a[0], "first");
        ASSERT_STREQ(a[1], "foo");
        ASSERT_STREQ(a[2], "bar");
        ASSERT_STREQ(a[3], "three");
        ASSERT_NULL(a[4]);

        ASSERT_OK(strv_consume_prepend(&a, strdup("first2")));
        ASSERT_STREQ(a[0], "first2");
        ASSERT_STREQ(a[1], "first");
        ASSERT_STREQ(a[2], "foo");
        ASSERT_STREQ(a[3], "bar");
        ASSERT_STREQ(a[4], "three");
        ASSERT_NULL(a[5]);
}

TEST(strv_push_with_size) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0;
        char *i, *j;

        ASSERT_NOT_NULL(i = strdup("foo"));
        ASSERT_OK(strv_push_with_size(&a, &n, i));
        ASSERT_EQ(n, 1U);

        ASSERT_NOT_NULL(i = strdup("a"));
        ASSERT_NOT_NULL(j = strdup("b"));
        ASSERT_OK(strv_push_with_size(&a, &n, i));
        ASSERT_EQ(n, 2U);
        ASSERT_OK(strv_push_with_size(&a, &n, j));
        ASSERT_EQ(n, 3U);

        ASSERT_STREQ(a[0], "foo");
        ASSERT_STREQ(a[1], "a");
        ASSERT_STREQ(a[2], "b");
        ASSERT_STREQ(a[3], NULL);

        ASSERT_EQ(strv_length(a), n);
}

TEST(strv_push) {
        _cleanup_strv_free_ char **a = NULL;
        char *i, *j;

        ASSERT_NOT_NULL(i = strdup("foo"));
        ASSERT_OK(strv_push(&a, i));

        ASSERT_NOT_NULL(i = strdup("a"));
        ASSERT_NOT_NULL(j = strdup("b"));
        ASSERT_OK(strv_push_pair(&a, i, j));

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

        a = ASSERT_NOT_NULL(strv_new("one", "two", "three"));
        b = ASSERT_NOT_NULL(strv_new("one", "two", "three"));
        c = ASSERT_NOT_NULL(strv_new("one", "two", "three", "four"));
        d = ASSERT_NOT_NULL(strv_new(NULL));

        ASSERT_EQ(strv_compare(a, a), 0);
        ASSERT_EQ(strv_compare(a, b), 0);
        ASSERT_EQ(strv_compare(d, d), 0);
        ASSERT_EQ(strv_compare(d, NULL), 0);
        ASSERT_EQ(strv_compare(NULL, NULL), 0);

        ASSERT_LT(strv_compare(a, c), 0);
        ASSERT_LT(strv_compare(b, c), 0);
        ASSERT_EQ(strv_compare(b, d), 1);
        ASSERT_EQ(strv_compare(b, NULL), 1);
}

TEST(strv_is_uniq) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = ASSERT_NOT_NULL(strv_new(NULL));
        ASSERT_TRUE(strv_is_uniq(a));

        b = ASSERT_NOT_NULL(strv_new("foo"));
        ASSERT_TRUE(strv_is_uniq(b));

        c = ASSERT_NOT_NULL(strv_new("foo", "bar"));
        ASSERT_TRUE(strv_is_uniq(c));

        d = ASSERT_NOT_NULL(strv_new("foo", "bar", "waldo", "bar", "piep"));
        ASSERT_FALSE(strv_is_uniq(d));
}

TEST(strv_reverse) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = ASSERT_NOT_NULL(strv_new(NULL));

        strv_reverse(a);
        ASSERT_TRUE(strv_isempty(a));

        b = ASSERT_NOT_NULL(strv_new("foo"));
        strv_reverse(b);
        ASSERT_STREQ(b[0], "foo");
        ASSERT_STREQ(b[1], NULL);

        c = ASSERT_NOT_NULL(strv_new("foo", "bar"));
        strv_reverse(c);
        ASSERT_STREQ(c[0], "bar");
        ASSERT_STREQ(c[1], "foo");
        ASSERT_STREQ(c[2], NULL);

        d = ASSERT_NOT_NULL(strv_new("foo", "bar", "waldo"));
        strv_reverse(d);
        ASSERT_STREQ(d[0], "waldo");
        ASSERT_STREQ(d[1], "bar");
        ASSERT_STREQ(d[2], "foo");
        ASSERT_STREQ(d[3], NULL);
}

TEST(strv_shell_escape) {
        _cleanup_strv_free_ char **v = NULL;

        v = ASSERT_NOT_NULL(strv_new("foo:bar", "bar,baz", "wal\\do"));
        ASSERT_NOT_NULL(strv_shell_escape(v, ",:"));
        ASSERT_STREQ(v[0], "foo\\:bar");
        ASSERT_STREQ(v[1], "bar\\,baz");
        ASSERT_STREQ(v[2], "wal\\\\do");
        ASSERT_STREQ(v[3], NULL);
}

static void test_strv_skip_one(char **a, size_t n, char **b) {
        a = strv_skip(a, n);
        ASSERT_STRV_EQ(a, b);
}

TEST(strv_skip) {
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 0, STRV_MAKE("foo", "bar", "baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 1, STRV_MAKE("bar", "baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 2, STRV_MAKE("baz"));
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 3, NULL);
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 4, NULL);
        test_strv_skip_one(STRV_MAKE("foo", "bar", "baz"), 55, NULL);

        test_strv_skip_one(STRV_MAKE("quux"), 0, STRV_MAKE("quux"));
        test_strv_skip_one(STRV_MAKE("quux"), 1, NULL);
        test_strv_skip_one(STRV_MAKE("quux"), 55, NULL);

        test_strv_skip_one(STRV_MAKE(NULL), 0, NULL);
        test_strv_skip_one(STRV_MAKE(NULL), 1, NULL);
        test_strv_skip_one(STRV_MAKE(NULL), 55, NULL);

        test_strv_skip_one(NULL, 0, NULL);
        test_strv_skip_one(NULL, 1, NULL);
        test_strv_skip_one(NULL, 55, NULL);
}

TEST(strv_extend_n) {
        _cleanup_strv_free_ char **v = NULL;

        v = ASSERT_NOT_NULL(strv_new("foo", "bar"));

        ASSERT_OK(strv_extend_n(&v, "waldo", 3));
        ASSERT_OK(strv_extend_n(&v, "piep", 2));

        ASSERT_STREQ(v[0], "foo");
        ASSERT_STREQ(v[1], "bar");
        ASSERT_STREQ(v[2], "waldo");
        ASSERT_STREQ(v[3], "waldo");
        ASSERT_STREQ(v[4], "waldo");
        ASSERT_STREQ(v[5], "piep");
        ASSERT_STREQ(v[6], "piep");
        ASSERT_NULL(v[7]);

        v = strv_free(v);

        ASSERT_OK(strv_extend_n(&v, "foo", 1));
        ASSERT_OK(strv_extend_n(&v, "bar", 0));

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
        ASSERT_EQ(i, 3U);

        FOREACH_STRING(x, "zzz")
                ASSERT_STREQ(x, "zzz");
}

TEST(strv_fnmatch) {
        _cleanup_strv_free_ char **v = NULL;
        size_t pos;

        ASSERT_FALSE(strv_fnmatch(STRV_EMPTY, "a"));

        v = strv_new("xxx", "*\\*", "yyy");
        ASSERT_FALSE(strv_fnmatch_full(v, "\\", /* flags= */ 0, /* ret_matched_pos= */ NULL));
        ASSERT_TRUE(strv_fnmatch_full(v, "\\", FNM_NOESCAPE, &pos));
        ASSERT_EQ(pos, 1U);
}

TEST(strv_extend_join) {
        _cleanup_strv_free_ char **v = NULL;

        ASSERT_OK(strv_extend_assignment(&v, "MESSAGE", "ABC"));
        ASSERT_OK(strv_extend_assignment(&v, "ABC", "QER"));
        ASSERT_OK(strv_extend_assignment(&v, "MISSING", /* rhs= */ NULL));

        ASSERT_EQ(strv_length(v), 2U);
        ASSERT_STREQ(v[0], "MESSAGE=ABC");
        ASSERT_STREQ(v[1], "ABC=QER");
}

TEST(STRV_EMPTY) {
        char **a = (char*[]) { NULL };   /* a != NULL, a[0] == NULL: empty strv  */
        char **b = (char**)  { NULL };   /* b == NULL: no array at all           */
        char **c = STRV_EMPTY;

        ASSERT_NOT_NULL(a);
        ASSERT_NULL(b);
        ASSERT_NOT_NULL(c);

        ASSERT_NULL(a[0]);
        ASSERT_NULL(c[0]);
}

TEST(strv_copy_n) {
        char **x = STRV_MAKE("a", "b", "c", "d", "e");
        _cleanup_strv_free_ char **l = NULL;

        l = strv_copy_n(x, 0);
        ASSERT_STRV_EQ(l, NULL);
        strv_free(l);

        l = strv_copy_n(x, 0);
        ASSERT_STRV_EQ(l, STRV_EMPTY);
        strv_free(l);

        l = strv_copy_n(x, 1);
        ASSERT_STRV_EQ(l, STRV_MAKE("a"));
        strv_free(l);

        l = strv_copy_n(x, 2);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b"));
        strv_free(l);

        l = strv_copy_n(x, 3);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b", "c"));
        strv_free(l);

        l = strv_copy_n(x, 4);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b", "c", "d"));
        strv_free(l);

        l = strv_copy_n(x, 5);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b", "c", "d", "e"));
        strv_free(l);

        l = strv_copy_n(x, 6);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b", "c", "d", "e"));
        strv_free(l);

        l = strv_copy_n(x, SIZE_MAX);
        ASSERT_STRV_EQ(l, STRV_MAKE("a", "b", "c", "d", "e"));
}

TEST(strv_find_first_field) {
        char **haystack = STRV_MAKE("a", "b", "c", "d", "e", "f", "g", "h", "i", "j");

        ASSERT_NULL(strv_find_first_field(/* needles= */ NULL, /* haystack= */ NULL));
        ASSERT_NULL(strv_find_first_field(/* needles= */ NULL, haystack));
        ASSERT_NULL(strv_find_first_field(STRV_MAKE("k", "l", "m", "d", "b"), /* haystack= */ NULL));
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

        ASSERT_OK(strv_extend_many(&l, NULL));
        ASSERT_TRUE(strv_isempty(l));

        ASSERT_OK(strv_extend_many(&l, NULL, NULL, NULL));
        ASSERT_TRUE(strv_isempty(l));

        ASSERT_OK(strv_extend_many(&l, "foo"));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo"));

        ASSERT_OK(strv_extend_many(&l, NULL, "bar", NULL));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar"));

        ASSERT_OK(strv_extend_many(&l, "waldo", "quux"));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar", "waldo", "quux"));

        ASSERT_OK(strv_extend_many(&l, "1", "2", "3", "4"));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar", "waldo", "quux", "1", "2", "3", "4"));

        ASSERT_OK(strv_extend_many(&l, "yes", NULL, "no"));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar", "waldo", "quux", "1", "2", "3", "4", "yes", "no"));
}

TEST(strv_rebreak_lines) {
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(strv_rebreak_lines(NULL, SIZE_MAX, &l));
        ASSERT_STRV_EQ(l, NULL);
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE(""), SIZE_MAX, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE(""));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("", ""), SIZE_MAX, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("", ""));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo"), SIZE_MAX, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo", "bar"), SIZE_MAX, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("Foo fOo foO FOo", "bar Bar bAr baR BAr"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("Foo fOo", "foO FOo", "bar Bar", "bAr baR", "BAr"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("           foo               ",
                                               "             foo bar               waldo quux         "),
                                     10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("           foo",
                                    "             foo",
                                    "bar",
                                    "waldo quux"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("            ",
                                               "\tfoo bar\t",
                                               "FOO\tBAR"),
                                     10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("",
                                    "\tfoo",
                                    "bar",
                                    "FOO",
                                    "BAR"));
        l = strv_free(l);

        /* Now make sure that breaking the lines a 2nd time does not modify the output anymore */
        for (size_t i = 1; i < 100; i++) {
                _cleanup_strv_free_ char **a = NULL, **b = NULL;

                ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foobar waldo waldo quux piep\tschnurz    pimm"), i, &a));
                ASSERT_OK(strv_rebreak_lines(a, i, &b));

                ASSERT_STRV_EQ(a, b);
        }

        /* Invalid UTF-8 is refused rather than measured. Previously a truncated multibyte lead byte at the
         * end of a line was blind-skipped by its expected length, stepping over the NUL and reading past
         * the end of the string. */
        ASSERT_ERROR(strv_rebreak_lines(STRV_MAKE("foo\xF0"), 10, &l), EINVAL);
        ASSERT_NULL(l);

        ASSERT_ERROR(strv_rebreak_lines(STRV_MAKE("bar\xFC"), 10, &l), EINVAL);
        ASSERT_NULL(l);

        /* Same, but reached after a line break, i.e. with the scan restarted at the character following
         * the whitespace we broke at. */
        ASSERT_ERROR(strv_rebreak_lines(STRV_MAKE("a \xF0" "b"), 3, &l), EINVAL);
        ASSERT_NULL(l);

        /* Newlines embedded in the input are hard line breaks. Previously everything before such a newline
         * was silently dropped if nothing but whitespace followed it. */
        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo\n"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo\n   "), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo\nbar"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo   \n   bar   \n"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "   bar"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo\n\nbar"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "", "bar"));
        l = strv_free(l);

        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("foo\r\nbar\r\n"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("foo", "bar"));
        l = strv_free(l);

        /* And the resulting lines are properly broken to the requested width, rather than staying glued
         * together in a single, over-long entry. */
        ASSERT_OK(strv_rebreak_lines(STRV_MAKE("hello world\nfoo bar baz quux waldo"), 10, &l));
        ASSERT_STRV_EQ(l, STRV_MAKE("hello", "world", "foo bar", "baz quux", "waldo"));
        l = strv_free(l);
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

TEST(strv_filter_prefix) {
        char **base = STRV_MAKE("foo", "bar", "baz", "foox", "zzz", "farb", "foerb");

        _cleanup_strv_free_ char **x = ASSERT_PTR(strv_filter_prefix(base, "fo"));
        ASSERT_STRV_EQ(x, STRV_MAKE("foo", "foox", "foerb"));
        x = strv_free(x);

        x = ASSERT_PTR(strv_filter_prefix(base, ""));
        ASSERT_STRV_EQ(x, base);
        x = strv_free(x);

        x = ASSERT_PTR(strv_filter_prefix(base, "z"));
        ASSERT_STRV_EQ(x, STRV_MAKE("zzz"));
        x = strv_free(x);

        x = ASSERT_PTR(strv_filter_prefix(base, "zzz"));
        ASSERT_STRV_EQ(x, STRV_MAKE("zzz"));
}

DEFINE_TEST_MAIN(LOG_INFO);
