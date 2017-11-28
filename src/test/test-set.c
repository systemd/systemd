/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "set.h"

static void test_set_steal_first(void) {
        _cleanup_set_free_ Set *m = NULL;
        int seen[3] = {};
        char *val;

        m = set_new(&string_hash_ops);
        assert_se(m);

        assert_se(set_put(m, (void*) "1") == 1);
        assert_se(set_put(m, (void*) "22") == 1);
        assert_se(set_put(m, (void*) "333") == 1);

        while ((val = set_steal_first(m)))
                seen[strlen(val) - 1]++;

        assert_se(seen[0] == 1 && seen[1] == 1 && seen[2] == 1);

        assert_se(set_isempty(m));
}

typedef struct Item {
        int seen;
} Item;
static void item_seen(Item *item) {
        item->seen++;
}

static void test_set_free_with_destructor(void) {
        Set *m;
        struct Item items[4] = {};
        unsigned i;

        assert_se(m = set_new(NULL));
        for (i = 0; i < ELEMENTSOF(items) - 1; i++)
                assert_se(set_put(m, items + i) == 1);

        m = set_free_with_destructor(m, item_seen);
        assert_se(items[0].seen == 1);
        assert_se(items[1].seen == 1);
        assert_se(items[2].seen == 1);
        assert_se(items[3].seen == 0);
}

static void test_set_put(void) {
        _cleanup_set_free_ Set *m = NULL;

        m = set_new(&string_hash_ops);
        assert_se(m);

        assert_se(set_put(m, (void*) "1") == 1);
        assert_se(set_put(m, (void*) "22") == 1);
        assert_se(set_put(m, (void*) "333") == 1);
        assert_se(set_put(m, (void*) "333") == 0);
        assert_se(set_remove(m, (void*) "333"));
        assert_se(set_put(m, (void*) "333") == 1);
        assert_se(set_put(m, (void*) "333") == 0);
        assert_se(set_put(m, (void*) "22") == 0);
}

static void test_set_make(void) {
        _cleanup_set_free_ Set *s = NULL;

        assert_se(set_make(&s, NULL, UINT_TO_PTR(4), UINT_TO_PTR(6), UINT_TO_PTR(8), NULL) == 0);
        assert_se(set_size(s) == 3);
        assert_se(!set_contains(s, UINT_TO_PTR(0)));
        assert_se(!set_contains(s, UINT_TO_PTR(1)));
        assert_se(!set_contains(s, UINT_TO_PTR(2)));
        assert_se(!set_contains(s, UINT_TO_PTR(3)));
        assert_se(set_contains(s, UINT_TO_PTR(4)));
        assert_se(!set_contains(s, UINT_TO_PTR(5)));
        assert_se(set_contains(s, UINT_TO_PTR(6)));
        assert_se(!set_contains(s, UINT_TO_PTR(7)));
        assert_se(set_contains(s, UINT_TO_PTR(8)));
        assert_se(!set_contains(s, UINT_TO_PTR(9)));
        s = set_free(s);

        assert_se(set_make(&s, NULL, NULL) == 0);
        assert_se(set_size(s) == 0);
        assert_se(!set_contains(s, UINT_TO_PTR(0)));
        assert_se(!set_contains(s, UINT_TO_PTR(4)));
        assert_se(!set_contains(s, UINT_TO_PTR(6)));
        assert_se(!set_contains(s, UINT_TO_PTR(8)));
        s = set_free(s);

        assert_se(set_make(&s, NULL, UINT_TO_PTR(3), NULL) == 0);
        assert_se(set_size(s) == 1);
        assert_se(!set_contains(s, UINT_TO_PTR(0)));
        assert_se(!set_contains(s, UINT_TO_PTR(1)));
        assert_se(!set_contains(s, UINT_TO_PTR(2)));
        assert_se(set_contains(s, UINT_TO_PTR(3)));
        assert_se(!set_contains(s, UINT_TO_PTR(4)));

        assert_se(set_make(&s, NULL, UINT_TO_PTR(2), UINT_TO_PTR(5), NULL) == 0);
        assert_se(set_size(s) == 2);
        assert_se(!set_contains(s, UINT_TO_PTR(0)));
        assert_se(!set_contains(s, UINT_TO_PTR(1)));
        assert_se(set_contains(s, UINT_TO_PTR(2)));
        assert_se(!set_contains(s, UINT_TO_PTR(3)));
        assert_se(!set_contains(s, UINT_TO_PTR(4)));
        assert_se(set_contains(s, UINT_TO_PTR(5)));
        assert_se(!set_contains(s, UINT_TO_PTR(6)));
}

int main(int argc, const char *argv[]) {
        test_set_steal_first();
        test_set_free_with_destructor();
        test_set_put();
        test_set_make();

        return 0;
}
