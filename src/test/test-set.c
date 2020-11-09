/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "set.h"
#include "strv.h"

const bool mempool_use_allowed = VALGRIND;

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

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, void, trivial_hash_func, trivial_compare_func, Item, item_seen);

static void test_set_free_with_hash_ops(void) {
        Set *m;
        struct Item items[4] = {};
        unsigned i;

        assert_se(m = set_new(&item_hash_ops));
        for (i = 0; i < ELEMENTSOF(items) - 1; i++)
                assert_se(set_put(m, items + i) == 1);

        m = set_free(m);
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

        _cleanup_free_ char **t = set_get_strv(m);
        assert_se(strv_contains(t, "1"));
        assert_se(strv_contains(t, "22"));
        assert_se(strv_contains(t, "333"));
        assert_se(strv_length(t) == 3);
}

static void test_set_put_strdup(void) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_put_strdup(&m, "aaa") == 1);
        assert_se(set_put_strdup(&m, "aaa") == 0);
        assert_se(set_put_strdup(&m, "bbb") == 1);
        assert_se(set_put_strdup(&m, "bbb") == 0);
        assert_se(set_put_strdup(&m, "aaa") == 0);
        assert_se(set_size(m) == 2);
}

static void test_set_put_strdupv(void) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "aaa")) == 2);
        assert_se(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "ccc")) == 1);
        assert_se(set_size(m) == 3);
}

static void test_set_ensure_allocated(void) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_ensure_allocated(&m, &string_hash_ops) == 1);
        assert_se(set_ensure_allocated(&m, &string_hash_ops) == 0);
        assert_se(set_ensure_allocated(&m, NULL) == 0);
        assert_se(set_size(m) == 0);
}

static void test_set_ensure_put(void) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 1);
        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 0);
        assert_se(set_ensure_put(&m, NULL, "a") == 0);
        assert_se(set_ensure_put(&m, &string_hash_ops, "b") == 1);
        assert_se(set_ensure_put(&m, &string_hash_ops, "b") == 0);
        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 0);
        assert_se(set_size(m) == 2);
}

static void test_set_ensure_consume(void) {
        _cleanup_set_free_ Set *m = NULL;
        char *s, *t;

        assert_se(s = strdup("a"));
        assert_se(set_ensure_consume(&m, &string_hash_ops_free, s) == 1);

        assert_se(t = strdup("a"));
        assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

        assert_se(t = strdup("a"));
        assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

        assert_se(t = strdup("b"));
        assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 1);

        assert_se(t = strdup("b"));
        assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

        assert_se(set_size(m) == 2);
}

int main(int argc, const char *argv[]) {
        test_set_steal_first();
        test_set_free_with_destructor();
        test_set_free_with_hash_ops();
        test_set_put();
        test_set_put_strdup();
        test_set_put_strdupv();
        test_set_ensure_allocated();
        test_set_ensure_put();
        test_set_ensure_consume();

        return 0;
}
