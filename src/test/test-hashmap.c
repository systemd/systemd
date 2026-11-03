/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "strv.h"
#include "tests.h"

// NOLINTNEXTLINE(misc-use-internal-linkage)
unsigned custom_counter = 0;
static void custom_destruct(void* p) {
        custom_counter--;
        free(p);
}

// NOLINTBEGIN(misc-use-internal-linkage)
DEFINE_HASH_OPS_FULL(boring_hash_ops, char, string_hash_func, string_compare_func, free, char, free);
DEFINE_HASH_OPS_FULL(custom_hash_ops, char, string_hash_func, string_compare_func, custom_destruct, char, custom_destruct);
// NOLINTEND(misc-use-internal-linkage)

TEST(ordered_hashmap_next) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *m = NULL;

        ASSERT_NOT_NULL(m = ordered_hashmap_new(/* hash_ops= */ NULL));
        for (int i = -2; i <= 2; i++)
                ASSERT_OK_EQ(ordered_hashmap_put(m, INT_TO_PTR(i), INT_TO_PTR(i+10)), 1);
        for (int i = -2; i <= 1; i++)
                ASSERT_PTR_EQ(ordered_hashmap_next(m, INT_TO_PTR(i)), INT_TO_PTR(i+11));
        ASSERT_NULL(ordered_hashmap_next(m, INT_TO_PTR(2)));
        ASSERT_NULL(ordered_hashmap_next(NULL, INT_TO_PTR(1)));
        ASSERT_NULL(ordered_hashmap_next(m, INT_TO_PTR(3)));
}

TEST(uint64_compare_func) {
        const uint64_t a = 0x100, b = 0x101;

        ASSERT_EQ(uint64_compare_func(&a, &a), 0);
        ASSERT_EQ(uint64_compare_func(&a, &b), -1);
        ASSERT_EQ(uint64_compare_func(&b, &a), 1);
}

TEST(trivial_compare_func) {
        ASSERT_EQ(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('a')), 0);
        ASSERT_EQ(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('b')), -1);
        ASSERT_EQ(trivial_compare_func(INT_TO_PTR('b'), INT_TO_PTR('a')), 1);
}

TEST(string_compare_func) {
        ASSERT_NE(string_compare_func("fred", "wilma"), 0);
        ASSERT_EQ(string_compare_func("fred", "fred"), 0);
}

static void compare_cache(Hashmap *map, IteratedCache *cache) {
        const void **keys = NULL, **values = NULL;
        unsigned num, idx;
        void *k, *v;

        ASSERT_OK_ZERO(iterated_cache_get(cache, &keys, &values, &num));
        ASSERT_TRUE(num == 0 || keys);
        ASSERT_TRUE(num == 0 || values);

        idx = 0;
        HASHMAP_FOREACH_KEY(v, k, map) {
                ASSERT_PTR_EQ(v, values[idx]);
                ASSERT_PTR_EQ(k, keys[idx]);

                idx++;
        }

        ASSERT_EQ(idx, num);
}

TEST(iterated_cache) {
        Hashmap *m;
        IteratedCache *c;

        ASSERT_NOT_NULL(m = hashmap_new(/* hash_ops= */ NULL));
        ASSERT_NOT_NULL(c = hashmap_iterated_cache_new(m));
        compare_cache(m, c);

        for (int stage = 0; stage < 100; stage++) {
                for (int i = 0; i < 100; i++) {
                        int foo = stage * 1000 + i;

                        ASSERT_OK_EQ(hashmap_put(m, INT_TO_PTR(foo), INT_TO_PTR(foo + 777)), 1);
                }

                compare_cache(m, c);

                if (stage % 10 == 0) {
                        for (int i = 0; i < 100; i++) {
                                int foo = stage * 1000 + i;

                                ASSERT_PTR_EQ(hashmap_remove(m, INT_TO_PTR(foo)), INT_TO_PTR(foo + 777));
                        }

                        compare_cache(m, c);
                }
        }

        hashmap_clear(m);
        compare_cache(m, c);

        ASSERT_NULL(hashmap_free(m));
        ASSERT_NULL(iterated_cache_free(c));
}

TEST(hashmap_put_strdup) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        char *s;

        /* We don't have ordered_hashmap_put_strdup() yet. If it is added,
         * these tests should be moved to test-hashmap-plain.c. */

        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 1);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 0);
        ASSERT_ERROR(hashmap_put_strdup(&m, "foo", "BAR"), EEXIST);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 0);
        ASSERT_TRUE(hashmap_contains(m, "foo"));

        s = hashmap_get(m, "foo");
        ASSERT_STREQ(s, "bar");

        ASSERT_OK_EQ(hashmap_put_strdup(&m, "xxx", "bar"), 1);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "xxx", "bar"), 0);
        ASSERT_ERROR(hashmap_put_strdup(&m, "xxx", "BAR"), EEXIST);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "xxx", "bar"), 0);
        ASSERT_TRUE(hashmap_contains(m, "xxx"));

        s = hashmap_get(m, "xxx");
        ASSERT_STREQ(s, "bar");
}

TEST(hashmap_put_strdup_null) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        char *s;

        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 1);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 0);
        ASSERT_ERROR(hashmap_put_strdup(&m, "foo", NULL), EEXIST);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "foo", "bar"), 0);
        ASSERT_TRUE(hashmap_contains(m, "foo"));

        s = hashmap_get(m, "foo");
        ASSERT_STREQ(s, "bar");

        ASSERT_OK_EQ(hashmap_put_strdup(&m, "xxx", NULL), 1);
        ASSERT_ERROR(hashmap_put_strdup(&m, "xxx", "bar"), EEXIST);
        ASSERT_OK_EQ(hashmap_put_strdup(&m, "xxx", NULL), 0);
        ASSERT_TRUE(hashmap_contains(m, "xxx"));

        s = hashmap_get(m, "xxx");
        ASSERT_NULL(s);
}

TEST(hashmap_values_to_strv) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        ASSERT_OK_POSITIVE(hashmap_put_strdup(&m, "a", "A"));
        ASSERT_OK_POSITIVE(hashmap_put_strdup(&m, "b", "B"));
        ASSERT_OK_POSITIVE(hashmap_put_strdup(&m, "c", "B"));

        _cleanup_strv_free_ char **s = hashmap_values_to_strv(m);
        strv_sort(s);
        ASSERT_STRV_EQ(s, STRV_MAKE("A", "B", "B"));

        ASSERT_TRUE(hashmap_isempty(m));
}

/* This file tests in test-hashmap-plain.c, and tests in test-hashmap-ordered.c, which is generated
 * from test-hashmap-plain.c. Hashmap tests should be added to test-hashmap-plain.c, and here only if
 * they don't apply to ordered hashmaps. */

/* This variable allows us to assert that the tests from different compilation units were actually run. */
// NOLINTNEXTLINE(misc-use-internal-linkage)
int n_extern_tests_run = 0;

static int intro(void) {
        ASSERT_EQ(n_extern_tests_run, 0);
        return EXIT_SUCCESS;
}

static int outro(void) {
        /* Ensure hashmap and ordered_hashmap were tested. */
        ASSERT_EQ(n_extern_tests_run, 2);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_INFO, intro, outro);
