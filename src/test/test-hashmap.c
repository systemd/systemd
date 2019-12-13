/* SPDX-License-Identifier: LGPL-2.1+ */

#include "hashmap.h"
#include "util.h"

unsigned custom_counter = 0;
static void custom_destruct(void* p) {
        custom_counter--;
        free(p);
}

DEFINE_HASH_OPS_FULL(boring_hash_ops, char, string_hash_func, string_compare_func, free, char, free);
DEFINE_HASH_OPS_FULL(custom_hash_ops, char, string_hash_func, string_compare_func, custom_destruct, char, custom_destruct);

void test_hashmap_funcs(void);
void test_ordered_hashmap_funcs(void);

static void test_ordered_hashmap_next(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *m = NULL;
        int i;

        log_info("/* %s */", __func__);

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

static void compare_cache(Hashmap *map, IteratedCache *cache) {
        const void **keys = NULL, **values = NULL;
        unsigned num, idx;
        Iterator iter;
        void *k, *v;

        assert_se(iterated_cache_get(cache, &keys, &values, &num) == 0);
        assert_se(num == 0 || keys);
        assert_se(num == 0 || values);

        idx = 0;
        HASHMAP_FOREACH_KEY(v, k, map, iter) {
                assert_se(v == values[idx]);
                assert_se(k == keys[idx]);

                idx++;
        }

        assert_se(idx == num);
}

static void test_iterated_cache(void) {
        Hashmap *m;
        IteratedCache *c;

        log_info("/* %s */", __func__);

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

int main(int argc, const char *argv[]) {
        /* This file tests in test-hashmap-plain.c, and tests in test-hashmap-ordered.c, which is generated
         * from test-hashmap-plain.c. Hashmap tests should be added to test-hashmap-plain.c, and here only if
         * they don't apply to ordered hashmaps. */

        log_parse_environment();
        log_open();

        test_hashmap_funcs();
        test_ordered_hashmap_funcs();

        log_info("/************ non-shared tests ************/");

        test_ordered_hashmap_next();
        test_uint64_compare_func();
        test_trivial_compare_func();
        test_string_compare_func();
        test_iterated_cache();

        return 0;
}
