/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

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

#include <string.h>

#include "util.h"
#include "specifier.h"
#include "strv.h"

static void test_specifier_printf(void) {
        static const Specifier table[] = {
                { 'a', specifier_string, (char*) "AAAA" },
                { 'b', specifier_string, (char*) "BBBB" },
                { 'm', specifier_machine_id, NULL },
                { 'B', specifier_boot_id, NULL },
                { 'H', specifier_host_name, NULL },
                { 'v', specifier_kernel_release, NULL },
                {}
        };

        _cleanup_free_ char *w = NULL;
        int r;

        r = specifier_printf("xxx a=%a b=%b yyy", table, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);

        puts(w);
        assert_se(streq(w, "xxx a=AAAA b=BBBB yyy"));

        free(w);
        r = specifier_printf("machine=%m, boot=%B, host=%H, version=%v", table, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);
        puts(w);
}

static const char* const input_table_multiple[] = {
        "one",
        "two",
        "three",
        NULL,
};

static const char* const input_table_one[] = {
        "one",
        NULL,
};

static const char* const input_table_none[] = {
        NULL,
};

static const char* const input_table_quotes[] = {
        "\"",
        "'",
        "\"\"",
        "\\",
        "\\\\",
        NULL,
};
#define QUOTES_STRING                            \
        "\"\\\"\" "                              \
        "\"\\\'\" "                              \
        "\"\\\"\\\"\" "                          \
        "\"\\\\\" "                              \
        "\"\\\\\\\\\""

static const char * const input_table_spaces[] = {
        " ",
        "' '",
        "\" ",
        " \"",
        " \\\\ ",
        NULL,
};
#define SPACES_STRING                           \
        "\" \" "                                \
        "\"\\' \\'\" "                          \
        "\"\\\" \" "                            \
        "\" \\\"\" "                            \
        "\" \\\\\\\\ \""

static void test_strv_find(void) {
        assert_se(strv_find((char **)input_table_multiple, "three"));
        assert_se(!strv_find((char **)input_table_multiple, "four"));
}

static void test_strv_find_prefix(void) {
        assert_se(strv_find_prefix((char **)input_table_multiple, "o"));
        assert_se(strv_find_prefix((char **)input_table_multiple, "one"));
        assert_se(strv_find_prefix((char **)input_table_multiple, ""));
        assert_se(!strv_find_prefix((char **)input_table_multiple, "xxx"));
        assert_se(!strv_find_prefix((char **)input_table_multiple, "onee"));
}

static void test_strv_join(void) {
        _cleanup_free_ char *p = NULL, *q = NULL, *r = NULL, *s = NULL, *t = NULL;

        p = strv_join((char **)input_table_multiple, ", ");
        assert_se(p);
        assert_se(streq(p, "one, two, three"));

        q = strv_join((char **)input_table_multiple, ";");
        assert_se(q);
        assert_se(streq(q, "one;two;three"));

        r = strv_join((char **)input_table_multiple, NULL);
        assert_se(r);
        assert_se(streq(r, "one two three"));

        s = strv_join((char **)input_table_one, ", ");
        assert_se(s);
        assert_se(streq(s, "one"));

        t = strv_join((char **)input_table_none, ", ");
        assert_se(t);
        assert_se(streq(t, ""));
}

static void test_strv_quote_unquote(const char* const *split, const char *quoted) {
        _cleanup_free_ char *p;
        _cleanup_strv_free_ char **s;
        char **t;

        p = strv_join_quoted((char **)split);
        assert_se(p);
        printf("-%s- --- -%s-\n", p, quoted); /* fprintf deals with NULL, puts does not */
        assert_se(p);
        assert_se(streq(p, quoted));

        s = strv_split_quoted(quoted);
        assert_se(s);
        STRV_FOREACH(t, s) {
                assert_se(*t);
                assert_se(streq(*t, *split));
                split++;
        }
}

static void test_strv_quote_unquote2(const char *quoted, const char ** list) {
        _cleanup_strv_free_ char **s;
        unsigned i = 0;
        char **t;

        s = strv_split_quoted(quoted);
        assert_se(s);

        STRV_FOREACH(t, s)
                assert_se(streq(list[i++], *t));

        assert_se(list[i] == NULL);
}

static void test_strv_split(void) {
        char **s;
        unsigned i = 0;
        _cleanup_strv_free_ char **l = NULL;
        const char str[] = "one,two,three";

        l = strv_split(str, ",");

        assert(l);

        STRV_FOREACH(s, l) {
                assert_se(streq(*s, input_table_multiple[i++]));
        }
}

static void test_strv_split_newlines(void) {
        unsigned i = 0;
        char **s;
        _cleanup_strv_free_ char **l = NULL;
        const char str[] = "one\ntwo\nthree";

        l = strv_split_newlines(str);

        assert(l);

        STRV_FOREACH(s, l) {
                assert_se(streq(*s, input_table_multiple[i++]));
        }
}

static void test_strv_split_nulstr(void) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "str0\0str1\0str2\0str3\0";

        l = strv_split_nulstr (nulstr);
        assert_se(l);

        assert_se(streq(l[0], "str0"));
        assert_se(streq(l[1], "str1"));
        assert_se(streq(l[2], "str2"));
        assert_se(streq(l[3], "str3"));
}

static void test_strv_parse_nulstr(void) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "fuck\0fuck2\0fuck3\0\0fuck5\0\0xxx";

        l = strv_parse_nulstr(nulstr, sizeof(nulstr)-1);
        assert_se(l);
        puts("Parse nulstr:");
        strv_print(l);

        assert_se(streq(l[0], "fuck"));
        assert_se(streq(l[1], "fuck2"));
        assert_se(streq(l[2], "fuck3"));
        assert_se(streq(l[3], ""));
        assert_se(streq(l[4], "fuck5"));
        assert_se(streq(l[5], ""));
        assert_se(streq(l[6], "xxx"));
}

static void test_strv_overlap(void) {
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

static void test_strv_sort(void) {
        const char* input_table[] = {
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                NULL
        };

        strv_sort((char **)input_table);

        assert_se(streq(input_table[0], "CAPITAL LETTERS FIRST"));
        assert_se(streq(input_table[1], "apple"));
        assert_se(streq(input_table[2], "banana"));
        assert_se(streq(input_table[3], "citrus"));
        assert_se(streq(input_table[4], "durian"));
}

static void test_strv_extend_strv_concat(void) {
         _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("without", "suffix", NULL);
        b = strv_new("with", "suffix", NULL);
        assert_se(a);
        assert_se(b);

        assert_se(strv_extend_strv_concat(&a, b, "_suffix") >= 0);

        assert_se(streq(a[0], "without"));
        assert_se(streq(a[1], "suffix"));
        assert_se(streq(a[2], "with_suffix"));
        assert_se(streq(a[3], "suffix_suffix"));
}

static void test_strv_extend_strv(void) {
         _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("abc", "def", "ghi", NULL);
        b = strv_new("jkl", "mno", "pqr", NULL);
        assert_se(a);
        assert_se(b);

        assert_se(strv_extend_strv(&a, b) >= 0);

        assert_se(streq(a[0], "abc"));
        assert_se(streq(a[1], "def"));
        assert_se(streq(a[2], "ghi"));
        assert_se(streq(a[3], "jkl"));
        assert_se(streq(a[4], "mno"));
        assert_se(streq(a[5], "pqr"));

        assert_se(strv_length(a) == 6);
}

static void test_strv_extend(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("test", "test1", NULL);
        assert_se(a);
        assert_se(strv_extend(&a, "test2") >= 0);
        assert_se(strv_extend(&b, "test3") >= 0);

        assert_se(streq(a[0], "test"));
        assert_se(streq(a[1], "test1"));
        assert_se(streq(a[2], "test2"));
        assert_se(streq(b[0], "test3"));
}

static void test_strv_extendf(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new("test", "test1", NULL);
        assert_se(a);
        assert_se(strv_extendf(&a, "test2 %s %d %s", "foo", 128, "bar") >= 0);
        assert_se(strv_extendf(&b, "test3 %s %s %d", "bar", "foo", 128) >= 0);

        assert_se(streq(a[0], "test"));
        assert_se(streq(a[1], "test1"));
        assert_se(streq(a[2], "test2 foo 128 bar"));
        assert_se(streq(b[0], "test3 bar foo 128"));
}

static void test_strv_foreach(void) {
        _cleanup_strv_free_ char **a;
        unsigned i = 0;
        char **check;

        a = strv_new("one", "two", "three", NULL);

        assert_se(a);

        STRV_FOREACH(check, a) {
                assert_se(streq(*check, input_table_multiple[i++]));
        }
}

static void test_strv_foreach_backwards(void) {
        _cleanup_strv_free_ char **a;
        unsigned i = 2;
        char **check;

        a = strv_new("one", "two", "three", NULL);

        assert_se(a);

        STRV_FOREACH_BACKWARDS(check, a) {
                assert_se(streq_ptr(*check, input_table_multiple[i--]));
        }
}

static void test_strv_foreach_pair(void) {
        _cleanup_strv_free_ char **a = NULL;
        char **x, **y;

        a = strv_new("pair_one",   "pair_one",
                     "pair_two",   "pair_two",
                     "pair_three", "pair_three",
                     NULL);

        STRV_FOREACH_PAIR(x, y, a) {
                assert_se(streq(*x, *y));
        }
}

static void test_strv_from_stdarg_alloca_one(char **l, const char *first, ...) {
        char **j;
        unsigned i;

        j = strv_from_stdarg_alloca(first);

        for (i = 0;; i++) {
                assert_se(streq_ptr(l[i], j[i]));

                if (!l[i])
                        break;
        }
}

static void test_strv_from_stdarg_alloca(void) {
        test_strv_from_stdarg_alloca_one(STRV_MAKE("foo", "bar"), "foo", "bar", NULL);
        test_strv_from_stdarg_alloca_one(STRV_MAKE("foo"), "foo", NULL);
        test_strv_from_stdarg_alloca_one(STRV_MAKE_EMPTY, NULL);
}

int main(int argc, char *argv[]) {
        test_specifier_printf();
        test_strv_foreach();
        test_strv_foreach_backwards();
        test_strv_foreach_pair();
        test_strv_find();
        test_strv_find_prefix();
        test_strv_join();

        test_strv_quote_unquote(input_table_multiple, "\"one\" \"two\" \"three\"");
        test_strv_quote_unquote(input_table_one, "\"one\"");
        test_strv_quote_unquote(input_table_none, "");
        test_strv_quote_unquote(input_table_quotes, QUOTES_STRING);
        test_strv_quote_unquote(input_table_spaces, SPACES_STRING);

        test_strv_quote_unquote2("    foo=bar     \"waldo\"    zzz    ", (const char*[]) { "foo=bar", "waldo", "zzz", NULL });
        test_strv_quote_unquote2("", (const char*[]) { NULL });
        test_strv_quote_unquote2(" ", (const char*[]) { NULL });
        test_strv_quote_unquote2("   ", (const char*[]) { NULL });
        test_strv_quote_unquote2("   x", (const char*[]) { "x", NULL });
        test_strv_quote_unquote2("x   ", (const char*[]) { "x", NULL });
        test_strv_quote_unquote2("  x   ", (const char*[]) { "x", NULL });
        test_strv_quote_unquote2("  \"x\"   ", (const char*[]) { "x", NULL });
        test_strv_quote_unquote2("  \'x\'   ", (const char*[]) { "x", NULL });
        test_strv_quote_unquote2("  \'x\"\'   ", (const char*[]) { "x\"", NULL });
        test_strv_quote_unquote2("  \"x\'\"   ", (const char*[]) { "x\'", NULL });

        test_strv_split();
        test_strv_split_newlines();
        test_strv_split_nulstr();
        test_strv_parse_nulstr();
        test_strv_overlap();
        test_strv_sort();
        test_strv_extend_strv();
        test_strv_extend_strv_concat();
        test_strv_extend();
        test_strv_extendf();
        test_strv_from_stdarg_alloca();

        return 0;
}
