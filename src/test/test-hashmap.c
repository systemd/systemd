/***
  This file is part of systemd

  Copyright 2013 Daniel Buch

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

#include "util.h"
#include "hashmap.h"

void test_hashmap_funcs(void);
void test_ordered_hashmap_funcs(void);

static void test_ordered_hashmap_next(void) {
        OrderedHashmap *m;
        char *val1, *val2, *val3, *val4, *r;

        m = ordered_hashmap_new(&string_hash_ops);
        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);

        ordered_hashmap_put(m, "key 1", val1);
        ordered_hashmap_put(m, "key 2", val2);
        ordered_hashmap_put(m, "key 3", val3);
        ordered_hashmap_put(m, "key 4", val4);

        r = ordered_hashmap_next(m, "key 1");
        assert_se(streq(r, val2));
        r = ordered_hashmap_next(m, "key 2");
        assert_se(streq(r, val3));
        r = ordered_hashmap_next(m, "key 3");
        assert_se(streq(r, val4));
        r = ordered_hashmap_next(m, "key 4");
        assert_se(!r);
        r = ordered_hashmap_next(NULL, "key 1");
        assert_se(!r);
        r = ordered_hashmap_next(m, "key 5");
        assert_se(!r);

        ordered_hashmap_free_free(m);
}

static void test_uint64_compare_func(void) {
        const uint64_t a = 0x100, b = 0x101;

        assert_se(uint64_compare_func(&a, &a) == 0);
        assert_se(uint64_compare_func(&a, &b) == -1);
        assert_se(uint64_compare_func(&b, &a) == 1);
}

static void test_trivial_compare_func(void) {
        assert_se(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('a')) == 0);
        assert_se(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('b')) == -1);
        assert_se(trivial_compare_func(INT_TO_PTR('b'), INT_TO_PTR('a')) == 1);
}

static void test_string_compare_func(void) {
        assert_se(string_compare_func("fred", "wilma") != 0);
        assert_se(string_compare_func("fred", "fred") == 0);
}

int main(int argc, const char *argv[]) {
        test_hashmap_funcs();
        test_ordered_hashmap_funcs();

        test_ordered_hashmap_next();
        test_uint64_compare_func();
        test_trivial_compare_func();
        test_string_compare_func();
}
