/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "random-util.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

TEST(set_steal_first) {
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

TEST(set_free_with_destructor) {
        Set *m;
        struct Item items[4] = {};

        assert_se(m = set_new(NULL));
        for (size_t i = 0; i < ELEMENTSOF(items) - 1; i++)
                assert_se(set_put(m, items + i) == 1);

        m = set_free_with_destructor(m, item_seen);
        assert_se(items[0].seen == 1);
        assert_se(items[1].seen == 1);
        assert_se(items[2].seen == 1);
        assert_se(items[3].seen == 0);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, void, trivial_hash_func, trivial_compare_func, Item, item_seen);

TEST(set_free_with_hash_ops) {
        Set *m;
        struct Item items[4] = {};

        assert_se(m = set_new(&item_hash_ops));
        for (size_t i = 0; i < ELEMENTSOF(items) - 1; i++)
                assert_se(set_put(m, items + i) == 1);

        m = set_free(m);
        assert_se(items[0].seen == 1);
        assert_se(items[1].seen == 1);
        assert_se(items[2].seen == 1);
        assert_se(items[3].seen == 0);
}

TEST(set_put) {
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

TEST(set_put_strndup) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_put_strndup(&m, "12345", 0) == 1);
        assert_se(set_put_strndup(&m, "12345", 1) == 1);
        assert_se(set_put_strndup(&m, "12345", 2) == 1);
        assert_se(set_put_strndup(&m, "12345", 3) == 1);
        assert_se(set_put_strndup(&m, "12345", 4) == 1);
        assert_se(set_put_strndup(&m, "12345", 5) == 1);
        assert_se(set_put_strndup(&m, "12345", 6) == 0);

        assert_se(set_contains(m, ""));
        assert_se(set_contains(m, "1"));
        assert_se(set_contains(m, "12"));
        assert_se(set_contains(m, "123"));
        assert_se(set_contains(m, "1234"));
        assert_se(set_contains(m, "12345"));

        assert_se(set_size(m) == 6);
}

TEST(set_put_strdup) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_put_strdup(&m, "aaa") == 1);
        assert_se(set_put_strdup(&m, "aaa") == 0);
        assert_se(set_put_strdup(&m, "bbb") == 1);
        assert_se(set_put_strdup(&m, "bbb") == 0);
        assert_se(set_put_strdup(&m, "aaa") == 0);

        assert_se(set_contains(m, "aaa"));
        assert_se(set_contains(m, "bbb"));

        assert_se(set_size(m) == 2);
}

TEST(set_put_strdupv) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "aaa")) == 2);
        assert_se(set_put_strdupv(&m, STRV_MAKE("aaa", "aaa", "bbb", "bbb", "ccc")) == 1);

        assert_se(set_contains(m, "aaa"));
        assert_se(set_contains(m, "bbb"));
        assert_se(set_contains(m, "ccc"));

        assert_se(set_size(m) == 3);
}

TEST(set_ensure_allocated) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_ensure_allocated(&m, &string_hash_ops) == 1);
        assert_se(set_ensure_allocated(&m, &string_hash_ops) == 0);
        assert_se(set_ensure_allocated(&m, NULL) == 0);
        assert_se(set_isempty(m));
}

TEST(set_copy) {
        _cleanup_set_free_ Set *s = NULL;
        _cleanup_set_free_free_ Set *copy = NULL;
        char *key1, *key2, *key3, *key4;

        key1 = strdup("key1");
        assert_se(key1);
        key2 = strdup("key2");
        assert_se(key2);
        key3 = strdup("key3");
        assert_se(key3);
        key4 = strdup("key4");
        assert_se(key4);

        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, key1) >= 0);
        assert_se(set_put(s, key2) >= 0);
        assert_se(set_put(s, key3) >= 0);
        assert_se(set_put(s, key4) >= 0);

        copy = set_copy(s);
        assert_se(copy);

        assert_se(set_equal(s, copy));
}

TEST(set_ensure_put) {
        _cleanup_set_free_ Set *m = NULL;

        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 1);
        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 0);
        assert_se(set_ensure_put(&m, NULL, "a") == 0);
        assert_se(set_ensure_put(&m, &string_hash_ops, "b") == 1);
        assert_se(set_ensure_put(&m, &string_hash_ops, "b") == 0);
        assert_se(set_ensure_put(&m, &string_hash_ops, "a") == 0);
        assert_se(set_size(m) == 2);
}

TEST(set_ensure_consume) {
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

TEST(set_strjoin) {
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

TEST(set_equal) {
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

TEST(set_fnmatch) {
        _cleanup_set_free_ Set *match = NULL, *nomatch = NULL;

        assert_se(set_put_strdup(&match, "aaa") >= 0);
        assert_se(set_put_strdup(&match, "bbb*") >= 0);
        assert_se(set_put_strdup(&match, "*ccc") >= 0);

        assert_se(set_put_strdup(&nomatch, "a*") >= 0);
        assert_se(set_put_strdup(&nomatch, "bbb") >= 0);
        assert_se(set_put_strdup(&nomatch, "ccc*") >= 0);

        assert_se(set_fnmatch(NULL, NULL, ""));
        assert_se(set_fnmatch(NULL, NULL, "hoge"));

        assert_se(set_fnmatch(match, NULL, "aaa"));
        assert_se(set_fnmatch(match, NULL, "bbb"));
        assert_se(set_fnmatch(match, NULL, "bbbXXX"));
        assert_se(set_fnmatch(match, NULL, "ccc"));
        assert_se(set_fnmatch(match, NULL, "XXXccc"));
        assert_se(!set_fnmatch(match, NULL, ""));
        assert_se(!set_fnmatch(match, NULL, "aaaa"));
        assert_se(!set_fnmatch(match, NULL, "XXbbb"));
        assert_se(!set_fnmatch(match, NULL, "cccXX"));

        assert_se(set_fnmatch(NULL, nomatch, ""));
        assert_se(set_fnmatch(NULL, nomatch, "Xa"));
        assert_se(set_fnmatch(NULL, nomatch, "bbbb"));
        assert_se(set_fnmatch(NULL, nomatch, "XXXccc"));
        assert_se(!set_fnmatch(NULL, nomatch, "a"));
        assert_se(!set_fnmatch(NULL, nomatch, "aXXXX"));
        assert_se(!set_fnmatch(NULL, nomatch, "bbb"));
        assert_se(!set_fnmatch(NULL, nomatch, "ccc"));
        assert_se(!set_fnmatch(NULL, nomatch, "cccXXX"));

        assert_se(set_fnmatch(match, nomatch, "bbbbb"));
        assert_se(set_fnmatch(match, nomatch, "XXccc"));
        assert_se(!set_fnmatch(match, nomatch, ""));
        assert_se(!set_fnmatch(match, nomatch, "a"));
        assert_se(!set_fnmatch(match, nomatch, "aaa"));
        assert_se(!set_fnmatch(match, nomatch, "b"));
        assert_se(!set_fnmatch(match, nomatch, "bbb"));
        assert_se(!set_fnmatch(match, nomatch, "ccc"));
        assert_se(!set_fnmatch(match, nomatch, "ccccc"));
        assert_se(!set_fnmatch(match, nomatch, "cccXX"));
}

DEFINE_TEST_MAIN(LOG_INFO);
