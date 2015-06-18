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
        _cleanup_ordered_hashmap_free_ OrderedHashmap *m = NULL;
        int i;

        assert_se(m = ordered_hashmap_new(NULL));
        for (i = -2; i <= 2; i++)
                assert_se(ordered_hashmap_put(m, INT_TO_PTR(i), INT_TO_PTR(i+10)) == 1);
        for (i = -2; i <= 1; i++)
                assert_se(ordered_hashmap_next(m, INT_TO_PTR(i)) == INT_TO_PTR(i+11));
        assert_se(!ordered_hashmap_next(m, INT_TO_PTR(2)));
        assert_se(!ordered_hashmap_next(NULL, INT_TO_PTR(1)));
        assert_se(!ordered_hashmap_next(m, INT_TO_PTR(3)));
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
