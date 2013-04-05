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
        _cleanup_free_ char *w = NULL;

        const Specifier table[] = {
                { 'a', specifier_string, (char*) "AAAA" },
                { 'b', specifier_string, (char*) "BBBB" },
                { 0, NULL, NULL }
        };

        w = specifier_printf("xxx a=%a b=%b yyy", table, NULL);
        puts(w);

        assert_se(w);
        assert_se(streq(w, "xxx a=AAAA b=BBBB yyy"));
}

static void test_strv_find(void) {
        const char * const input_table[] = {
                "one",
                "two",
                "three",
                NULL
        };

        assert_se(strv_find((char **)input_table, "three"));
        assert_se(!strv_find((char **)input_table, "four"));
}

static void test_strv_find_prefix(void) {
        const char * const input_table[] = {
                "one",
                "two",
                "three",
                NULL
        };

        assert_se(strv_find_prefix((char **)input_table, "o"));
        assert_se(strv_find_prefix((char **)input_table, "one"));
        assert_se(strv_find_prefix((char **)input_table, ""));
        assert_se(!strv_find_prefix((char **)input_table, "xxx"));
        assert_se(!strv_find_prefix((char **)input_table, "onee"));
}

static void test_strv_join(void) {
        _cleanup_free_ char *p = NULL, *q = NULL, *r = NULL, *s = NULL, *t = NULL;

        const char * const input_table_multiple[] = {
                "one",
                "two",
                "three",
                NULL
        };
        const char * const input_table_one[] = {
                "one",
                NULL
        };
        const char * const input_table_none[] = {
                NULL
        };

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

static void test_strv_merge_concat(void) {
         _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL;

        a = strv_new("without", "suffix", NULL);
        b = strv_new("with", "suffix", NULL);
        assert_se(a);
        assert_se(b);

        c = strv_merge_concat(a, b, "_suffix");
        assert_se(c);

        assert_se(streq(c[0], "without"));
        assert_se(streq(c[1], "suffix"));
        assert_se(streq(c[2], "with_suffix"));
        assert_se(streq(c[3], "suffix_suffix"));
}

static void test_strv_merge(void) {
         _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL;

        a = strv_new("abc", "def", "ghi", NULL);
        b = strv_new("jkl", "mno", "pqr", NULL);
        assert_se(a);
        assert_se(b);

        c = strv_merge(a, b);
        assert_se(c);

        assert_se(streq(c[0], "abc"));
        assert_se(streq(c[1], "def"));
        assert_se(streq(c[2], "ghi"));
        assert_se(streq(c[3], "jkl"));
        assert_se(streq(c[4], "mno"));
        assert_se(streq(c[5], "pqr"));

        assert_se(strv_length(c) == 6);
}

static void test_strv_append(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL;

        a = strv_new("test", "test1", NULL);
        assert_se(a);
        b = strv_append(a, "test2");
        c = strv_append(NULL, "test3");
        assert_se(b);
        assert_se(c);

        assert_se(streq(b[0], "test"));
        assert_se(streq(b[1], "test1"));
        assert_se(streq(b[2], "test2"));
        assert_se(streq(c[0], "test3"));
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

int main(int argc, char *argv[]) {
        test_specifier_printf();
        test_strv_foreach_pair();
        test_strv_find();
        test_strv_find_prefix();
        test_strv_join();
        test_strv_split_nulstr();
        test_strv_parse_nulstr();
        test_strv_overlap();
        test_strv_sort();
        test_strv_merge();
        test_strv_merge_concat();
        test_strv_append();

        return 0;
}
