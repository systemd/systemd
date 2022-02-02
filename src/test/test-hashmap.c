/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

unsigned custom_counter = 0;
static void custom_destruct(void* p) {
        custom_counter--;
        free(p);
}

DEFINE_HASH_OPS_FULL(boring_hash_ops, char, string_hash_func, string_compare_func, free, char, free);
DEFINE_HASH_OPS_FULL(custom_hash_ops, char, string_hash_func, string_compare_func, custom_destruct, char, custom_destruct);

TEST(ordered_hashmap_next) {
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

TEST(uint64_compare_func) {
        const uint64_t a = 0x100, b = 0x101;

        assert_se(uint64_compare_func(&a, &a) == 0);
        assert_se(uint64_compare_func(&a, &b) == -1);
        assert_se(uint64_compare_func(&b, &a) == 1);
}

TEST(trivial_compare_func) {
        assert_se(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('a')) == 0);
        assert_se(trivial_compare_func(INT_TO_PTR('a'), INT_TO_PTR('b')) == -1);
        assert_se(trivial_compare_func(INT_TO_PTR('b'), INT_TO_PTR('a')) == 1);
}

TEST(string_compare_func) {
        assert_se(string_compare_func("fred", "wilma") != 0);
        assert_se(string_compare_func("fred", "fred") == 0);
}

static void compare_cache(Hashmap *map, IteratedCache *cache) {
        const void **keys = NULL, **values = NULL;
        unsigned num, idx;
        void *k, *v;

        assert_se(iterated_cache_get(cache, &keys, &values, &num) == 0);
        assert_se(num == 0 || keys);
        assert_se(num == 0 || values);

        idx = 0;
        HASHMAP_FOREACH_KEY(v, k, map) {
                assert_se(v == values[idx]);
                assert_se(k == keys[idx]);

                idx++;
        }

        assert_se(idx == num);
}

TEST(iterated_cache) {
        Hashmap *m;
        IteratedCache *c;

        assert_se(m = hashmap_new(NULL));
        assert_se(c = hashmap_iterated_cache_new(m));
        compare_cache(m, c);

        for (int stage = 0; stage < 100; stage++) {

                for (int i = 0; i < 100; i++) {
                        int foo = stage * 1000 + i;

                        assert_se(hashmap_put(m, INT_TO_PTR(foo), INT_TO_PTR(foo + 777)) == 1);
                }

                compare_cache(m, c);

                if (!(stage % 10)) {
                        for (int i = 0; i < 100; i++) {
                                int foo = stage * 1000 + i;

                                assert_se(hashmap_remove(m, INT_TO_PTR(foo)) == INT_TO_PTR(foo + 777));
                        }

                        compare_cache(m, c);
                }
        }

        hashmap_clear(m);
        compare_cache(m, c);

        assert_se(hashmap_free(m) == NULL);
        assert_se(iterated_cache_free(c) == NULL);
}

TEST(hashmap_put_strdup) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        char *s;

        /* We don't have ordered_hashmap_put_strdup() yet. If it is added,
         * these tests should be moved to test-hashmap-plain.c. */

        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 1);
        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 0);
        assert_se(hashmap_put_strdup(&m, "foo", "BAR") == -EEXIST);
        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 0);
        assert_se(hashmap_contains(m, "foo"));

        s = hashmap_get(m, "foo");
        assert_se(streq(s, "bar"));

        assert_se(hashmap_put_strdup(&m, "xxx", "bar") == 1);
        assert_se(hashmap_put_strdup(&m, "xxx", "bar") == 0);
        assert_se(hashmap_put_strdup(&m, "xxx", "BAR") == -EEXIST);
        assert_se(hashmap_put_strdup(&m, "xxx", "bar") == 0);
        assert_se(hashmap_contains(m, "xxx"));

        s = hashmap_get(m, "xxx");
        assert_se(streq(s, "bar"));
}

TEST(hashmap_put_strdup_null) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        char *s;

        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 1);
        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 0);
        assert_se(hashmap_put_strdup(&m, "foo", NULL) == -EEXIST);
        assert_se(hashmap_put_strdup(&m, "foo", "bar") == 0);
        assert_se(hashmap_contains(m, "foo"));

        s = hashmap_get(m, "foo");
        assert_se(streq(s, "bar"));

        assert_se(hashmap_put_strdup(&m, "xxx", NULL) == 1);
        assert_se(hashmap_put_strdup(&m, "xxx", "bar") == -EEXIST);
        assert_se(hashmap_put_strdup(&m, "xxx", NULL) == 0);
        assert_se(hashmap_contains(m, "xxx"));

        s = hashmap_get(m, "xxx");
        assert_se(s == NULL);
}

/* This file tests in test-hashmap-plain.c, and tests in test-hashmap-ordered.c, which is generated
 * from test-hashmap-plain.c. Hashmap tests should be added to test-hashmap-plain.c, and here only if
 * they don't apply to ordered hashmaps. */

/* This variable allows us to assert that the tests from different compilation units were actually run. */
int n_extern_tests_run = 0;

static int intro(void) {
        assert_se(n_extern_tests_run == 0);
        return EXIT_SUCCESS;
}

static int outro(void) {
        /* Ensure hashmap and ordered_hashmap were tested. */
        assert_se(n_extern_tests_run == 2);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_INFO, intro, outro);
