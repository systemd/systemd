/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "ordered-set.h"
#include "string-util.h"
#include "strv.h"

static void test_set_steal_first(void) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL;
        int seen[3] = {};
        char *val;

        m = ordered_set_new(&string_hash_ops);
        assert_se(m);

        assert_se(ordered_set_put(m, (void*) "1") == 1);
        assert_se(ordered_set_put(m, (void*) "22") == 1);
        assert_se(ordered_set_put(m, (void*) "333") == 1);

        ordered_set_print(stdout, "SET=", m);

        while ((val = ordered_set_steal_first(m)))
                seen[strlen(val) - 1]++;

        assert_se(seen[0] == 1 && seen[1] == 1 && seen[2] == 1);

        assert_se(ordered_set_isempty(m));

        ordered_set_print(stdout, "SET=", m);
}

typedef struct Item {
        int seen;
} Item;
static void item_seen(Item *item) {
        item->seen++;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, void, trivial_hash_func, trivial_compare_func, Item, item_seen);

static void test_set_free_with_hash_ops(void) {
        OrderedSet *m;
        struct Item items[4] = {};
        unsigned i;

        assert_se(m = ordered_set_new(&item_hash_ops));
        for (i = 0; i < ELEMENTSOF(items) - 1; i++)
                assert_se(ordered_set_put(m, items + i) == 1);

        m = ordered_set_free(m);
        assert_se(items[0].seen == 1);
        assert_se(items[1].seen == 1);
        assert_se(items[2].seen == 1);
        assert_se(items[3].seen == 0);
}

static void test_set_put(void) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL;
        _cleanup_free_ char **t = NULL;

        m = ordered_set_new(&string_hash_ops);
        assert_se(m);

        assert_se(ordered_set_put(m, (void*) "1") == 1);
        assert_se(ordered_set_put(m, (void*) "22") == 1);
        assert_se(ordered_set_put(m, (void*) "333") == 1);
        assert_se(ordered_set_put(m, (void*) "333") == 0);
        assert_se(ordered_set_remove(m, (void*) "333"));
        assert_se(ordered_set_put(m, (void*) "333") == 1);
        assert_se(ordered_set_put(m, (void*) "333") == 0);
        assert_se(ordered_set_put(m, (void*) "22") == 0);

        assert_se(t = ordered_set_get_strv(m));
        assert_se(streq(t[0], "1"));
        assert_se(streq(t[1], "22"));
        assert_se(streq(t[2], "333"));
        assert_se(!t[3]);

        ordered_set_print(stdout, "FOO=", m);
}

static void test_set_put_string_set(void) {
        _cleanup_ordered_set_free_free_ OrderedSet *m = NULL;
        _cleanup_ordered_set_free_ OrderedSet *q = NULL;
        _cleanup_free_ char **final = NULL; /* "just free" because the strings are in the set */
        void *t;

        m = ordered_set_new(&string_hash_ops);
        assert_se(m);

        q = ordered_set_new(&string_hash_ops);
        assert_se(q);

        assert_se(t = strdup("1"));
        assert_se(ordered_set_put(m, t) == 1);
        assert_se(t = strdup("22"));
        assert_se(ordered_set_put(m, t) == 1);
        assert_se(t = strdup("333"));
        assert_se(ordered_set_put(m, t) == 1);

        assert_se(ordered_set_put(q, (void*) "11") == 1);
        assert_se(ordered_set_put(q, (void*) "22") == 1);
        assert_se(ordered_set_put(q, (void*) "33") == 1);

        assert_se(ordered_set_put_string_set(m, q) == 2);

        assert_se(final = ordered_set_get_strv(m));
        assert_se(strv_equal(final, STRV_MAKE("1", "22", "333", "11", "33")));

        ordered_set_print(stdout, "BAR=", m);
}

int main(int argc, const char *argv[]) {
        test_set_steal_first();
        test_set_free_with_hash_ops();
        test_set_put();
        test_set_put_string_set();

        return 0;
}
