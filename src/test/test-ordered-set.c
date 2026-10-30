/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ordered-set.h"
#include "tests.h"

TEST(set_steal_first) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL;
        int seen[3] = {};
        char *val;

        m = ASSERT_NOT_NULL(ordered_set_new(&string_hash_ops));

        ASSERT_OK_EQ(ordered_set_put(m, (void*) "1"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "22"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "333"), 1);

        ordered_set_print(stdout, "SET=", m);

        while ((val = ordered_set_steal_first(m)))
                seen[strlen(val) - 1]++;

        ASSERT_EQ(seen[0], 1);
        ASSERT_EQ(seen[1], 1);
        ASSERT_EQ(seen[2], 1);

        ASSERT_TRUE(ordered_set_isempty(m));

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

        ASSERT_NOT_NULL(m = ordered_set_new(&item_hash_ops));

        FOREACH_ARRAY(item, items, ELEMENTSOF(items) - 1)
                ASSERT_OK_EQ(ordered_set_put(m, item), 1);

        FOREACH_ARRAY(item, items, ELEMENTSOF(items) - 1)
                ASSERT_OK_EQ(ordered_set_put(m, item), 0);  /* We get 0 here, because we use trivial hash
                                                             * ops. Also see below... */

        m = ordered_set_free(m);
        ASSERT_EQ(items[0].seen, 1);
        ASSERT_EQ(items[1].seen, 1);
        ASSERT_EQ(items[2].seen, 1);
        ASSERT_EQ(items[3].seen, 0);
}

TEST(set_put) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL;
        _cleanup_free_ char **t = NULL, *str = NULL;

        m = ASSERT_NOT_NULL(ordered_set_new(&string_hash_ops));

        ASSERT_OK_EQ(ordered_set_put(m, (void*) "1"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "22"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "333"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "333"), 0);
        ASSERT_NOT_NULL(ordered_set_remove(m, (void*) "333"));
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "333"), 1);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "333"), 0);
        ASSERT_OK_EQ(ordered_set_put(m, (void*) "22"), 0);

        ASSERT_NOT_NULL(str = strdup("333"));
        ASSERT_ERROR(ordered_set_put(m, str), EEXIST); /* ... and we get -EEXIST here, because we use
                                                        * non-trivial hash ops. */

        ASSERT_NOT_NULL(t = ordered_set_get_strv(m));
        ASSERT_STREQ(t[0], "1");
        ASSERT_STREQ(t[1], "22");
        ASSERT_STREQ(t[2], "333");
        ASSERT_NULL(t[3]);

        ordered_set_print(stdout, "FOO=", m);
}

TEST(set_put_string_set) {
        _cleanup_ordered_set_free_ OrderedSet *m = NULL, *q = NULL;
        _cleanup_free_ char **final = NULL; /* "just free" because the strings are in the set */

        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&m, "1"));
        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&m, "22"));
        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&m, "333"));

        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&q, "11"));
        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&q, "22"));
        ASSERT_OK_POSITIVE(ordered_set_put_strdup(&q, "33"));

        ASSERT_OK_POSITIVE(ordered_set_put_string_set(&m, q));
        ASSERT_OK_ZERO(ordered_set_put_string_set(&m, q));

        ASSERT_NOT_NULL(final = ordered_set_get_strv(m));
        ASSERT_STRV_EQ(final, STRV_MAKE("1", "22", "333", "11", "33"));

        ordered_set_print(stdout, "BAR=", m);
}

DEFINE_TEST_MAIN(LOG_INFO);
