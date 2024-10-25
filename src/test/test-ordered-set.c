/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "ordered-set.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(set_steal_first) {
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

TEST(set_free_with_hash_ops) {
        OrderedSet *m;
        struct Item items[4] = {};

        assert_se(m = ordered_set_new(&item_hash_ops));

        FOREACH_ARRAY(item, items, ELEMENTSOF(items) - 1)
                assert_se(ordered_set_put(m, item) == 1);

        FOREACH_ARRAY(item, items, ELEMENTSOF(items) - 1)
                assert_se(ordered_set_put(m, item) == 0);  /* We get 0 here, because we use trivial hash
                                                                 * ops. Also see below... */

        m = ordered_set_free(m);
        assert_se(items[0].seen == 1);
        assert_se(items[1].seen == 1);
        assert_se(items[2].seen == 1);
        assert_se(items[3].seen == 0);
}

TEST(set_put) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL;
        _cleanup_free_ char **t = NULL, *str = NULL;

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

        assert_se(str = strdup("333"));
        assert_se(ordered_set_put(m, str) == -EEXIST); /* ... and we get -EEXIST here, because we use
                                                        * non-trivial hash ops. */

        assert_se(t = ordered_set_get_strv(m));
        ASSERT_STREQ(t[0], "1");
        ASSERT_STREQ(t[1], "22");
        ASSERT_STREQ(t[2], "333");
        assert_se(!t[3]);

        ordered_set_print(stdout, "FOO=", m);
}

TEST(set_put_string_set) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL, *q = NULL;
        _cleanup_free_ char **final = NULL; /* "just free" because the strings are in the set */

        assert_se(ordered_set_put_strdup(&m, "1") == 1);
        assert_se(ordered_set_put_strdup(&m, "22") == 1);
        assert_se(ordered_set_put_strdup(&m, "333") == 1);

        assert_se(ordered_set_put_strdup(&q, "11") == 1);
        assert_se(ordered_set_put_strdup(&q, "22") == 1);
        assert_se(ordered_set_put_strdup(&q, "33") == 1);

        assert_se(ordered_set_put_string_set(&m, q) == 2);

        assert_se(final = ordered_set_get_strv(m));
        assert_se(strv_equal(final, STRV_MAKE("1", "22", "333", "11", "33")));

        ordered_set_print(stdout, "BAR=", m);
}

DEFINE_TEST_MAIN(LOG_INFO);
