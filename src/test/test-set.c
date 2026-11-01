/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "strv.h"
#include "tests.h"

TEST(set_steal_first) {
        _cleanup_set_free_ Set *m = NULL;
        int seen[3] = {};
        char *val;

        m = ASSERT_NOT_NULL(set_new(&string_hash_ops));

        ASSERT_OK_EQ(set_put(m, (void*) "1"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "22"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "333"), 1);

        while ((val = set_steal_first(m)))
                seen[strlen(val) - 1]++;

        ASSERT_EQ(seen[0], 1);
        ASSERT_EQ(seen[1], 1);
        ASSERT_EQ(seen[2], 1);

        ASSERT_TRUE(set_isempty(m));
}

typedef struct Item {
        int seen;
} Item;
static void item_seen(Item *item) {
        item->seen++;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, void, trivial_hash_func, trivial_compare_func, Item, item_seen);

TEST(set_free_with_hash_ops) {
        Set *m;
        struct Item items[4] = {};

        ASSERT_NOT_NULL(m = set_new(&item_hash_ops));
        FOREACH_ARRAY(item, items, ELEMENTSOF(items) - 1)
                ASSERT_OK_EQ(set_put(m, item), 1);

        m = set_free(m);
        ASSERT_EQ(items[0].seen, 1);
        ASSERT_EQ(items[1].seen, 1);
        ASSERT_EQ(items[2].seen, 1);
        ASSERT_EQ(items[3].seen, 0);
}

static unsigned set_ensure_consume_freed = 0;

typedef struct ValItem {
        int key;
} ValItem;

static void val_item_free(ValItem *i) {
        set_ensure_consume_freed++;
        free(i);
}

static void val_item_hash_func(const ValItem *i, struct siphash *state) {
        siphash24_compress_typesafe(i->key, state);
}

static int val_item_compare_func(const ValItem *a, const ValItem *b) {
        return CMP(a->key, b->key);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                val_item_hash_ops, ValItem, val_item_hash_func, val_item_compare_func,
                ValItem, val_item_free);

TEST(set_ensure_consume_value_destructor) {
        _cleanup_set_free_ Set *s = NULL;
        ValItem *a, *b;

        ASSERT_NOT_NULL(a = new0(ValItem, 1));
        a->key = 1;
        ASSERT_OK_POSITIVE(set_ensure_consume(&s, &val_item_hash_ops, a));

        ASSERT_NOT_NULL(b = new0(ValItem, 1));
        b->key = 1; /* same key, different pointer -> duplicate */

        set_ensure_consume_freed = 0;
        /* The rejected duplicate must be released via the value destructor, not plain free(). */
        ASSERT_OK_ZERO(set_ensure_consume(&s, &val_item_hash_ops, b));
        ASSERT_EQ(set_ensure_consume_freed, 1u);
}

TEST(set_put) {
        _cleanup_set_free_ Set *m = NULL;

        m = ASSERT_NOT_NULL(set_new(&string_hash_ops));

        ASSERT_OK_EQ(set_put(m, (void*) "1"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "22"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "333"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "333"), 0);
        ASSERT_NOT_NULL(set_remove(m, (void*) "333"));
        ASSERT_OK_EQ(set_put(m, (void*) "333"), 1);
        ASSERT_OK_EQ(set_put(m, (void*) "333"), 0);
        ASSERT_OK_EQ(set_put(m, (void*) "22"), 0);

        _cleanup_free_ char **t = set_get_strv(m);
        ASSERT_TRUE(strv_contains(t, "1"));
        ASSERT_TRUE(strv_contains(t, "22"));
        ASSERT_TRUE(strv_contains(t, "333"));
        ASSERT_EQ(strv_length(t), 3U);
}

TEST(set_put_strndup) {
        _cleanup_set_free_ Set *m = NULL;

        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 0), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 1), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 2), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 3), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 4), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 5), 1);
        ASSERT_OK_EQ(set_put_strndup(&m, "12345", 6), 0);

        ASSERT_TRUE(set_contains(m, ""));
        ASSERT_TRUE(set_contains(m, "1"));
        ASSERT_TRUE(set_contains(m, "12"));
        ASSERT_TRUE(set_contains(m, "123"));
        ASSERT_TRUE(set_contains(m, "1234"));
        ASSERT_TRUE(set_contains(m, "12345"));

        ASSERT_EQ(set_size(m), 6U);
}

TEST(set_put_strdup) {
        _cleanup_set_free_ Set *m = NULL;

        ASSERT_OK_EQ(set_put_strdup(&m, "aaa"), 1);
        ASSERT_OK_EQ(set_put_strdup(&m, "aaa"), 0);
        ASSERT_OK_EQ(set_put_strdup(&m, "bbb"), 1);
        ASSERT_OK_EQ(set_put_strdup(&m, "bbb"), 0);
        ASSERT_OK_EQ(set_put_strdup(&m, "aaa"), 0);

        ASSERT_TRUE(set_contains(m, "aaa"));
        ASSERT_TRUE(set_contains(m, "bbb"));

        ASSERT_EQ(set_size(m), 2U);
}

TEST(set_put_strdupv) {
        _cleanup_set_free_ Set *m = NULL;

        ASSERT_OK_EQ(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "aaa")), 2);
        ASSERT_OK_EQ(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "ccc")), 1);

        ASSERT_TRUE(set_contains(m, "aaa"));
        ASSERT_TRUE(set_contains(m, "bbb"));
        ASSERT_TRUE(set_contains(m, "ccc"));

        ASSERT_EQ(set_size(m), 3U);
}

TEST(set_ensure_allocated) {
        _cleanup_set_free_ Set *m = NULL;

        ASSERT_OK_POSITIVE(set_ensure_allocated(&m, &string_hash_ops));
        ASSERT_OK_ZERO(set_ensure_allocated(&m, &string_hash_ops));
        ASSERT_SIGNAL(set_ensure_allocated(&m, /* hash_ops= */ NULL), SIGABRT);
        ASSERT_TRUE(set_isempty(m));
}

TEST(set_copy) {
        _cleanup_set_free_ Set *s = NULL, *copy = NULL;
        _cleanup_free_ char *key1 = NULL, *key2 = NULL, *key3 = NULL, *key4 = NULL;

        key1 = ASSERT_NOT_NULL(strdup("key1"));
        key2 = ASSERT_NOT_NULL(strdup("key2"));
        key3 = ASSERT_NOT_NULL(strdup("key3"));
        key4 = ASSERT_NOT_NULL(strdup("key4"));

        s = ASSERT_NOT_NULL(set_new(&string_hash_ops));

        ASSERT_OK(set_put(s, key1));
        ASSERT_OK(set_put(s, key2));
        ASSERT_OK(set_put(s, key3));
        ASSERT_OK(set_put(s, key4));

        copy = set_copy(s);
        ASSERT_NOT_NULL(copy);

        ASSERT_TRUE(set_equal(s, copy));
}

TEST(set_ensure_put) {
        _cleanup_set_free_ Set *m = NULL;

        ASSERT_OK_POSITIVE(set_ensure_put(&m, &string_hash_ops, "a"));
        ASSERT_OK_ZERO(set_ensure_put(&m, &string_hash_ops, "a"));
        ASSERT_SIGNAL(set_ensure_put(&m, /* hash_ops= */ NULL, "a"), SIGABRT);
        ASSERT_OK_POSITIVE(set_ensure_put(&m, &string_hash_ops, "b"));
        ASSERT_OK_ZERO(set_ensure_put(&m, &string_hash_ops, "b"));
        ASSERT_OK_ZERO(set_ensure_put(&m, &string_hash_ops, "a"));
        ASSERT_EQ(set_size(m), 2u);
}

TEST(set_ensure_consume) {
        _cleanup_set_free_ Set *m = NULL;
        char *s, *t;

        ASSERT_NOT_NULL(s = strdup("a"));
        ASSERT_OK_EQ(set_ensure_consume(&m, &string_hash_ops_free, s), 1);

        ASSERT_NOT_NULL(t = strdup("a"));
        ASSERT_OK_EQ(set_ensure_consume(&m, &string_hash_ops_free, t), 0);

        ASSERT_NOT_NULL(t = strdup("a"));
        ASSERT_OK_EQ(set_ensure_consume(&m, &string_hash_ops_free, t), 0);

        ASSERT_NOT_NULL(t = strdup("b"));
        ASSERT_OK_EQ(set_ensure_consume(&m, &string_hash_ops_free, t), 1);

        ASSERT_NOT_NULL(t = strdup("b"));
        ASSERT_OK_EQ(set_ensure_consume(&m, &string_hash_ops_free, t), 0);

        ASSERT_EQ(set_size(m), 2U);
}

TEST(set_strjoin) {
        _cleanup_set_free_ Set *m = NULL;
        _cleanup_free_ char *joined = NULL;

        /* Empty set */
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ false, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ false, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ false, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ false, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ true, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ true, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ true, &joined));
        ASSERT_NULL(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ true, &joined));
        ASSERT_NULL(joined);

        /* Single entry */
        ASSERT_OK_EQ(set_put_strdup(&m, "aaa"), 1);
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ false, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ false, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ false, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ false, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ true, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ true, &joined));
        ASSERT_STREQ(joined, "aaa");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ true, &joined));
        ASSERT_STREQ(joined, " aaa ");
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ true, &joined));
        ASSERT_STREQ(joined, "xxxaaaxxx");

        /* Two entries */
        ASSERT_OK_EQ(set_put_strdup(&m, "bbb"), 1);
        ASSERT_OK_EQ(set_put_strdup(&m, "aaa"), 0);
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ false, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ false, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ false, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaa bbb", "bbb aaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ false, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaaxxxbbb", "bbbxxxaaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, /* separator= */ NULL, /* wrap_with_separator= */ true, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "", /* wrap_with_separator= */ true, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "aaabbb", "bbbaaa"));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, " ", /* wrap_with_separator= */ true, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, " aaa bbb ", " bbb aaa "));
        joined = mfree(joined);
        ASSERT_OK(set_strjoin(m, "xxx", /* wrap_with_separator= */ true, &joined));
        ASSERT_TRUE(STR_IN_SET(joined, "xxxaaaxxxbbbxxx", "xxxbbbxxxaaaxxx"));
}

TEST(set_equal) {
        _cleanup_set_free_ Set *a = NULL, *b = NULL;
        void *p;

        ASSERT_NOT_NULL(a = set_new(/* hash_ops= */ NULL));
        ASSERT_NOT_NULL(b = set_new(/* hash_ops= */ NULL));

        ASSERT_TRUE(set_equal(a, a));
        ASSERT_TRUE(set_equal(b, b));
        ASSERT_TRUE(set_equal(a, b));
        ASSERT_TRUE(set_equal(b, a));
        ASSERT_TRUE(set_equal(NULL, a));
        ASSERT_TRUE(set_equal(NULL, b));
        ASSERT_TRUE(set_equal(a, NULL));
        ASSERT_TRUE(set_equal(b, NULL));
        ASSERT_TRUE(set_equal(NULL, NULL));

        for (unsigned i = 0; i < 333; i++) {
                p = INT32_TO_PTR(1 + (random_u32() & 0xFFFU));

                ASSERT_OK_OR(set_put(a, p), -EEXIST);
        }

        ASSERT_OK(set_put(a, INT32_TO_PTR(0x1000U)));

        ASSERT_GE(set_size(a), 2U);
        ASSERT_LE(set_size(a), 334U);

        ASSERT_FALSE(set_equal(a, b));
        ASSERT_FALSE(set_equal(b, a));
        ASSERT_FALSE(set_equal(a, NULL));

        SET_FOREACH(p, a)
                ASSERT_OK(set_put(b, p));

        ASSERT_TRUE(set_equal(a, b));
        ASSERT_TRUE(set_equal(b, a));

        ASSERT_PTR_EQ(set_remove(a, INT32_TO_PTR(0x1000U)), INT32_TO_PTR(0x1000U));

        ASSERT_FALSE(set_equal(a, b));
        ASSERT_FALSE(set_equal(b, a));

        ASSERT_PTR_EQ(set_remove(b, INT32_TO_PTR(0x1000U)), INT32_TO_PTR(0x1000U));

        ASSERT_TRUE(set_equal(a, b));
        ASSERT_TRUE(set_equal(b, a));

        ASSERT_OK(set_put(b, INT32_TO_PTR(0x1001U)));

        ASSERT_FALSE(set_equal(a, b));
        ASSERT_FALSE(set_equal(b, a));

        ASSERT_OK(set_put(a, INT32_TO_PTR(0x1001U)));

        ASSERT_TRUE(set_equal(a, b));
        ASSERT_TRUE(set_equal(b, a));

        set_clear(a);

        ASSERT_FALSE(set_equal(a, b));
        ASSERT_FALSE(set_equal(b, a));

        set_clear(b);

        ASSERT_TRUE(set_equal(a, b));
        ASSERT_TRUE(set_equal(b, a));
}

TEST(set_fnmatch) {
        _cleanup_set_free_ Set *match = NULL, *nomatch = NULL;

        ASSERT_OK(set_put_strdup(&match, "aaa"));
        ASSERT_OK(set_put_strdup(&match, "bbb*"));
        ASSERT_OK(set_put_strdup(&match, "*ccc"));

        ASSERT_OK(set_put_strdup(&nomatch, "a*"));
        ASSERT_OK(set_put_strdup(&nomatch, "bbb"));
        ASSERT_OK(set_put_strdup(&nomatch, "ccc*"));

        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, /* exclude_patterns= */ NULL, ""));
        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, /* exclude_patterns= */ NULL, "hoge"));

        ASSERT_TRUE(set_fnmatch(match, /* exclude_patterns= */ NULL, "aaa"));
        ASSERT_TRUE(set_fnmatch(match, /* exclude_patterns= */ NULL, "bbb"));
        ASSERT_TRUE(set_fnmatch(match, /* exclude_patterns= */ NULL, "bbbXXX"));
        ASSERT_TRUE(set_fnmatch(match, /* exclude_patterns= */ NULL, "ccc"));
        ASSERT_TRUE(set_fnmatch(match, /* exclude_patterns= */ NULL, "XXXccc"));
        ASSERT_FALSE(set_fnmatch(match, /* exclude_patterns= */ NULL, ""));
        ASSERT_FALSE(set_fnmatch(match, /* exclude_patterns= */ NULL, "aaaa"));
        ASSERT_FALSE(set_fnmatch(match, /* exclude_patterns= */ NULL, "XXbbb"));
        ASSERT_FALSE(set_fnmatch(match, /* exclude_patterns= */ NULL, "cccXX"));

        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, nomatch, ""));
        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "Xa"));
        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "bbbb"));
        ASSERT_TRUE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "XXXccc"));
        ASSERT_FALSE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "a"));
        ASSERT_FALSE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "aXXXX"));
        ASSERT_FALSE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "bbb"));
        ASSERT_FALSE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "ccc"));
        ASSERT_FALSE(set_fnmatch(/* include_patterns= */ NULL, nomatch, "cccXXX"));

        ASSERT_TRUE(set_fnmatch(match, nomatch, "bbbbb"));
        ASSERT_TRUE(set_fnmatch(match, nomatch, "XXccc"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, ""));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "a"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "aaa"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "b"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "bbb"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "ccc"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "ccccc"));
        ASSERT_FALSE(set_fnmatch(match, nomatch, "cccXX"));
}

TEST(set_to_strv) {
        _cleanup_set_free_ Set *set = NULL;
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char **b = NULL;
        char **v = STRV_MAKE("aaa", "bbb", "ccc");

        ASSERT_NOT_NULL(a = set_to_strv(&set));
        ASSERT_TRUE(strv_isempty(a));
        ASSERT_NULL(set);
        a = strv_free(a);

        ASSERT_OK(set_put_strdupv(&set, v));
        ASSERT_EQ(set_size(set), strv_length(v));

        ASSERT_NOT_NULL(b = set_get_strv(set));
        ASSERT_EQ(strv_length(b), strv_length(v));
        ASSERT_TRUE(strv_equal_ignore_order(b, v));

        ASSERT_NOT_NULL(a = set_to_strv(&set));
        ASSERT_EQ(strv_length(a), strv_length(v));
        ASSERT_TRUE(strv_equal_ignore_order(a, v));
        ASSERT_NULL(set);
}

DEFINE_TEST_MAIN(LOG_INFO);
