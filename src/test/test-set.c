/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "random-util.h"
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

static void test_set_strjoin(void) {
        _cleanup_set_free_ Set *m = NULL;
        _cleanup_free_ char *joined = NULL;

        /* Empty set */
        assert_se(set_strjoin(m, NULL, false, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, "", false, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, " ", false, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, "xxx", false, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, NULL, true, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, "", true, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, " ", true, &joined) >= 0);
        assert_se(!joined);
        assert_se(set_strjoin(m, "xxx", true, &joined) >= 0);
        assert_se(!joined);

        /* Single entry */
        assert_se(set_put_strdup(&m, "aaa") == 1);
        assert_se(set_strjoin(m, NULL, false, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "", false, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, " ", false, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "xxx", false, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, NULL, true, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "", true, &joined) >= 0);
        assert_se(streq(joined, "aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, " ", true, &joined) >= 0);
        assert_se(streq(joined, " aaa "));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "xxx", true, &joined) >= 0);
        assert_se(streq(joined, "xxxaaaxxx"));

        /* Two entries */
        assert_se(set_put_strdup(&m, "bbb") == 1);
        assert_se(set_put_strdup(&m, "aaa") == 0);
        joined = mfree(joined);
        assert_se(set_strjoin(m, NULL, false, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "", false, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, " ", false, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaa bbb", "bbb aaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "xxx", false, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaaxxxbbb", "bbbxxxaaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, NULL, true, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "", true, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        assert_se(set_strjoin(m, " ", true, &joined) >= 0);
        assert_se(STR_IN_SET(joined, " aaa bbb ", " bbb aaa "));
        joined = mfree(joined);
        assert_se(set_strjoin(m, "xxx", true, &joined) >= 0);
        assert_se(STR_IN_SET(joined, "xxxaaaxxxbbbxxx", "xxxbbbxxxaaaxxx"));
}

static void test_set_equal(void) {
        _cleanup_set_free_ Set *a = NULL, *b = NULL;
        void *p;
        int r;

        assert_se(a = set_new(NULL));
        assert_se(b = set_new(NULL));

        assert_se(set_equal(a, a));
        assert_se(set_equal(b, b));
        assert_se(set_equal(a, b));
        assert_se(set_equal(b, a));
        assert_se(set_equal(NULL, a));
        assert_se(set_equal(NULL, b));
        assert_se(set_equal(a, NULL));
        assert_se(set_equal(b, NULL));
        assert_se(set_equal(NULL, NULL));

        for (unsigned i = 0; i < 333; i++) {
                p = INT32_TO_PTR(1 + (random_u32() & 0xFFFU));

                r = set_put(a, p);
                assert_se(r >= 0 || r == -EEXIST);
        }

        assert_se(set_put(a, INT32_TO_PTR(0x1000U)) >= 0);

        assert_se(set_size(a) >= 2);
        assert_se(set_size(a) <= 334);

        assert_se(!set_equal(a, b));
        assert_se(!set_equal(b, a));
        assert_se(!set_equal(a, NULL));

        SET_FOREACH(p, a)
                assert_se(set_put(b, p) >= 0);

        assert_se(set_equal(a, b));
        assert_se(set_equal(b, a));

        assert_se(set_remove(a, INT32_TO_PTR(0x1000U)) == INT32_TO_PTR(0x1000U));

        assert_se(!set_equal(a, b));
        assert_se(!set_equal(b, a));

        assert_se(set_remove(b, INT32_TO_PTR(0x1000U)) == INT32_TO_PTR(0x1000U));

        assert_se(set_equal(a, b));
        assert_se(set_equal(b, a));

        assert_se(set_put(b, INT32_TO_PTR(0x1001U)) >= 0);

        assert_se(!set_equal(a, b));
        assert_se(!set_equal(b, a));

        assert_se(set_put(a, INT32_TO_PTR(0x1001U)) >= 0);

        assert_se(set_equal(a, b));
        assert_se(set_equal(b, a));

        set_clear(a);

        assert_se(!set_equal(a, b));
        assert_se(!set_equal(b, a));

        set_clear(b);

        assert_se(set_equal(a, b));
        assert_se(set_equal(b, a));
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
        test_set_strjoin();
        test_set_equal();

        return 0;
}
