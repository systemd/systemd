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
        char *w;

        const Specifier table[] = {
                { 'a', specifier_string, (char*) "AAAA" },
                { 'b', specifier_string, (char*) "BBBB" },
                { 0, NULL, NULL }
        };

        w = specifier_printf("xxx a=%a b=%b yyy", table, NULL);
        printf("<%s>\n", w);
        free(w);
}

static void test_strv_find(void) {
        const char * const input_table[] = {
                "one",
                "two",
                "three",
                NULL
        };

        assert(strv_find((char **)input_table, "three"));
        assert(!strv_find((char **)input_table, "four"));
}

static void test_strv_find_prefix(void) {
        const char * const input_table[] = {
                "one",
                "two",
                "three",
                NULL
        };

        assert(strv_find_prefix((char **)input_table, "o"));
        assert(strv_find_prefix((char **)input_table, "one"));
        assert(strv_find_prefix((char **)input_table, ""));
        assert(!strv_find_prefix((char **)input_table, "xxx"));
        assert(!strv_find_prefix((char **)input_table, "onee"));
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
        assert(streq(p, "one, two, three"));

        q = strv_join((char **)input_table_multiple, ";");
        assert(streq(q, "one;two;three"));

        r = strv_join((char **)input_table_multiple, NULL);
        assert(streq(r, "one two three"));

        s = strv_join((char **)input_table_one, ", ");
        assert(streq(s, "one"));

        t = strv_join((char **)input_table_none, ", ");
        assert(streq(t, ""));
}

static void test_strv_parse_nulstr(void) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "fuck\0fuck2\0fuck3\0\0fuck5\0\0xxx";

        l = strv_parse_nulstr(nulstr, sizeof(nulstr)-1);
        puts("Parse nulstr:");
        strv_print(l);

        assert(streq(l[0], "fuck"));
        assert(streq(l[1], "fuck2"));
        assert(streq(l[2], "fuck3"));
        assert(streq(l[3], ""));
        assert(streq(l[4], "fuck5"));
        assert(streq(l[5], ""));
        assert(streq(l[6], "xxx"));
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

        assert(strv_overlap((char **)input_table, (char**)input_table_overlap));
        assert(!strv_overlap((char **)input_table, (char**)input_table_unique));
}

static void test_strv_sort(void) {
        const char * const input_table[] = {
                "durian",
                "apple",
                "citrus",
                 "CAPITAL LETTERS FIRST",
                "banana",
                NULL
        };

        strv_sort((char **)input_table);

        assert(streq(input_table[0], "CAPITAL LETTERS FIRST"));
        assert(streq(input_table[1], "apple"));
        assert(streq(input_table[2], "banana"));
        assert(streq(input_table[3], "citrus"));
        assert(streq(input_table[4], "durian"));
}

int main(int argc, char *argv[]) {
        test_specifier_printf();
        test_strv_find();
        test_strv_find_prefix();
        test_strv_join();
        test_strv_parse_nulstr();
        test_strv_overlap();
        test_strv_sort();

        return 0;
}
