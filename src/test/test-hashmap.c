/***
  This file is part of systemd

  Copyright 2013 Daniel Buch

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include "strv.h"
#include "util.h"
#include "hashmap.h"

static void test_hashmap_replace(void) {
        Hashmap *m;
        char *val1, *val2, *val3, *val4, *val5, *r;

        m = hashmap_new(string_hash_func, string_compare_func);

        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);
        val5 = strdup("val5");
        assert_se(val5);

        hashmap_put(m, "key 1", val1);
        hashmap_put(m, "key 2", val2);
        hashmap_put(m, "key 3", val3);
        hashmap_put(m, "key 4", val4);

        hashmap_replace(m, "key 3", val1);
        r = hashmap_get(m, "key 3");
        assert_se(streq(r, "val1"));

        hashmap_replace(m, "key 5", val5);
        r = hashmap_get(m, "key 5");
        assert_se(streq(r, "val5"));

        free(val1);
        free(val2);
        free(val3);
        free(val4);
        free(val5);
        hashmap_free(m);
}

static void test_hashmap_copy(void) {
        Hashmap *m, *copy;
        char *val1, *val2, *val3, *val4, *r;

        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "key 1", val1);
        hashmap_put(m, "key 2", val2);
        hashmap_put(m, "key 3", val3);
        hashmap_put(m, "key 4", val4);

        copy = hashmap_copy(m);

        r = hashmap_get(copy, "key 1");
        assert_se(streq(r, "val1"));
        r = hashmap_get(copy, "key 2");
        assert_se(streq(r, "val2"));
        r = hashmap_get(copy, "key 3");
        assert_se(streq(r, "val3"));
        r = hashmap_get(copy, "key 4");
        assert_se(streq(r, "val4"));

        hashmap_free_free(copy);
        hashmap_free(m);
}

static void test_hashmap_get_strv(void) {
        Hashmap *m;
        char **strv;
        char *val1, *val2, *val3, *val4;

        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "key 1", val1);
        hashmap_put(m, "key 2", val2);
        hashmap_put(m, "key 3", val3);
        hashmap_put(m, "key 4", val4);

        strv = hashmap_get_strv(m);

        assert_se(streq(strv[0], "val1"));
        assert_se(streq(strv[1], "val2"));
        assert_se(streq(strv[2], "val3"));
        assert_se(streq(strv[3], "val4"));

        strv_free(strv);

        hashmap_free(m);
}

static void test_hashmap_move_one(void) {
        Hashmap *m, *n;
        char *val1, *val2, *val3, *val4, *r;

        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);
        n = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "key 1", val1);
        hashmap_put(m, "key 2", val2);
        hashmap_put(m, "key 3", val3);
        hashmap_put(m, "key 4", val4);

        hashmap_move_one(n, m, "key 3");
        hashmap_move_one(n, m, "key 4");

        r = hashmap_get(n, "key 3");
        assert_se(r && streq(r, "val3"));
        r = hashmap_get(n, "key 4");
        assert_se(r && streq(r, "val4"));
        r = hashmap_get(m, "key 3");
        assert_se(!r);


        hashmap_free_free(m);
        hashmap_free_free(n);
}

static void test_hashmap_next(void) {
        Hashmap *m;
        char *val1, *val2, *val3, *val4, *r;

        m = hashmap_new(string_hash_func, string_compare_func);
        val1 = strdup("val1");
        assert_se(val1);
        val2 = strdup("val2");
        assert_se(val2);
        val3 = strdup("val3");
        assert_se(val3);
        val4 = strdup("val4");
        assert_se(val4);

        hashmap_put(m, "key 1", val1);
        hashmap_put(m, "key 2", val2);
        hashmap_put(m, "key 3", val3);
        hashmap_put(m, "key 4", val4);

        r = hashmap_next(m, "key 1");
        assert_se(streq(r, val2));
        r = hashmap_next(m, "key 2");
        assert_se(streq(r, val3));
        r = hashmap_next(m, "key 3");
        assert_se(streq(r, val4));
        r = hashmap_next(m, "key 4");
        assert_se(!r);

        hashmap_free_free(m);
}

static void test_hashmap_update(void) {
        Hashmap *m;
        char *val1, *val2, *r;

        m = hashmap_new(string_hash_func, string_compare_func);
        val1 = strdup("old_value");
        assert_se(val1);
        val2 = strdup("new_value");
        assert_se(val2);

        hashmap_put(m, "key 1", val1);
        r = hashmap_get(m, "key 1");
        assert_se(streq(r, "old_value"));

        hashmap_update(m, "key 1", val2);
        r = hashmap_get(m, "key 1");
        assert_se(streq(r, "new_value"));

        free(val1);
        free(val2);
        hashmap_free(m);
}

static void test_hashmap_put(void) {
        Hashmap *m;
        int valid_hashmap_put;

        m = hashmap_new(string_hash_func, string_compare_func);

        valid_hashmap_put = hashmap_put(m, "key 1", (void*) (const char *) "val 1");
        assert_se(valid_hashmap_put == 1);

        assert_se(m);
        hashmap_free(m);
}

static void test_hashmap_remove_and_put(void) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        int valid;
        char *r;

        m = hashmap_new(string_hash_func, string_compare_func);
        assert_se(m);

        valid = hashmap_remove_and_put(m, "unvalid key", "new key", NULL);
        assert_se(valid < 0);

        valid = hashmap_put(m, "key 1", (void*) (const char *) "val 1");
        assert_se(valid == 1);
        valid = hashmap_remove_and_put(m, "key 1", "key 2", (void*) (const char *) "val 2");
        assert_se(valid == 0);

        r = hashmap_get(m, "key 2");
        assert_se(streq(r, "val 2"));
        assert_se(!hashmap_get(m, "key 1"));

        valid = hashmap_put(m, "key 3", (void*) (const char *) "val 3");
        assert_se(valid == 1);
        valid = hashmap_remove_and_put(m, "key 3", "key 2", (void*) (const char *) "val 2");
        assert_se(valid < 0);
}

static void test_hashmap_ensure_allocated(void) {
        Hashmap *m;
        int valid_hashmap;

        m = hashmap_new(string_hash_func, string_compare_func);

        valid_hashmap = hashmap_ensure_allocated(&m, string_hash_func, string_compare_func);
        assert_se(valid_hashmap == 0);

        assert_se(m);
        hashmap_free(m);
}

static void test_hashmap_foreach_key(void) {
        Hashmap *m;
        Iterator i;
        bool key_found[] = { false, false, false, false };
        const char *s;
        const char *key;
        static const char key_table[] =
                "key 1\0"
                "key 2\0"
                "key 3\0"
                "key 4\0";

        m = hashmap_new(string_hash_func, string_compare_func);

        NULSTR_FOREACH(key, key_table)
                hashmap_put(m, key, (void*) (const char*) "my dummy val");

        HASHMAP_FOREACH_KEY(s, key, m, i) {
                if (!key_found[0] && streq(key, "key 1"))
                        key_found[0] = true;
                else if (!key_found[1] && streq(key, "key 2"))
                        key_found[1] = true;
                else if (!key_found[2] && streq(key, "key 3"))
                        key_found[2] = true;
                else if (!key_found[3] && streq(key, "fail"))
                        key_found[3] = true;
        }

        assert_se(m);
        assert_se(key_found[0] && key_found[1] && key_found[2] && !key_found[3]);

        hashmap_free(m);
}

static void test_hashmap_foreach(void) {
        Hashmap *m;
        Iterator i;
        bool value_found[] = { false, false, false, false };
        char *val1, *val2, *val3, *val4, *s;

        val1 = strdup("my val1");
        assert_se(val1);
        val2 = strdup("my val2");
        assert_se(val2);
        val3 = strdup("my val3");
        assert_se(val3);
        val4 = strdup("my val4");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "Key 1", val1);
        hashmap_put(m, "Key 2", val2);
        hashmap_put(m, "Key 3", val3);
        hashmap_put(m, "Key 4", val4);

        HASHMAP_FOREACH(s, m, i) {
                if (!value_found[0] && streq(s, val1))
                        value_found[0] = true;
                else if (!value_found[1] && streq(s, val2))
                        value_found[1] = true;
                else if (!value_found[2] && streq(s, val3))
                        value_found[2] = true;
                else if (!value_found[3] && streq(s, val4))
                        value_found[3] = true;
        }

        assert_se(m);
        assert_se(value_found[0] && value_found[1] && value_found[2] && value_found[3]);

        hashmap_free_free(m);
}

static void test_hashmap_foreach_backwards(void) {
        Hashmap *m;
        Iterator i;
        char *val1, *val2, *val3, *val4, *s;
        bool value_found[] = { false, false, false, false };

        val1 = strdup("my val1");
        assert_se(val1);
        val2 = strdup("my val2");
        assert_se(val2);
        val3 = strdup("my val3");
        assert_se(val3);
        val4 = strdup("my val4");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);
        hashmap_put(m, "Key 1", val1);
        hashmap_put(m, "Key 2", val2);
        hashmap_put(m, "Key 3", val3);
        hashmap_put(m, "Key 4", val4);

        HASHMAP_FOREACH_BACKWARDS(s, m, i) {
                if (!value_found[0] && streq(s, val1))
                        value_found[0] = true;
                else if (!value_found[1] && streq(s, val2))
                        value_found[1] = true;
                else if (!value_found[2] && streq(s, val3))
                        value_found[2] = true;
                else if (!value_found[3] && streq(s, val4))
                        value_found[3] = true;
        }

        assert_se(m);
        assert_se(value_found[0] && value_found[1] && value_found[2] && value_found[3]);

        hashmap_free_free(m);
}

static void test_hashmap_merge(void) {
        Hashmap *m;
        Hashmap *n;
        char *val1, *val2, *val3, *val4, *r;

        val1 = strdup("my val1");
        assert_se(val1);
        val2 = strdup("my val2");
        assert_se(val2);
        val3 = strdup("my val3");
        assert_se(val3);
        val4 = strdup("my val4");
        assert_se(val4);

        n = hashmap_new(string_hash_func, string_compare_func);
        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "Key 1", val1);
        hashmap_put(m, "Key 2", val2);
        hashmap_put(n, "Key 3", val3);
        hashmap_put(n, "Key 4", val4);

        assert_se(hashmap_merge(m, n) == 0);
        r = hashmap_get(m, "Key 3");
        assert_se(r && streq(r, "my val3"));
        r = hashmap_get(m, "Key 4");
        assert_se(r && streq(r, "my val4"));

        assert_se(n);
        assert_se(m);
        hashmap_free(n);
        hashmap_free_free(m);
}

static void test_hashmap_contains(void) {
        Hashmap *m;
        char *val1;

        val1 = strdup("my val");
        assert_se(val1);

        m = hashmap_new(string_hash_func, string_compare_func);

        assert_se(!hashmap_contains(m, "Key 1"));
        hashmap_put(m, "Key 1", val1);
        assert_se(hashmap_contains(m, "Key 1"));

        assert_se(m);
        hashmap_free_free(m);
}

static void test_hashmap_isempty(void) {
        Hashmap *m;
        char *val1;

        val1 = strdup("my val");
        assert_se(val1);

        m = hashmap_new(string_hash_func, string_compare_func);

        assert_se(hashmap_isempty(m));
        hashmap_put(m, "Key 1", val1);
        assert_se(!hashmap_isempty(m));

        assert_se(m);
        hashmap_free_free(m);
}

static void test_hashmap_size(void) {
        Hashmap *m;
        char *val1, *val2, *val3, *val4;

        val1 = strdup("my val");
        assert_se(val1);
        val2 = strdup("my val");
        assert_se(val2);
        val3 = strdup("my val");
        assert_se(val3);
        val4 = strdup("my val");
        assert_se(val4);

        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "Key 1", val1);
        hashmap_put(m, "Key 2", val2);
        hashmap_put(m, "Key 3", val3);
        hashmap_put(m, "Key 4", val4);

        assert_se(m);
        assert_se(hashmap_size(m) == 4);
        hashmap_free_free(m);
}

static void test_hashmap_get(void) {
        Hashmap *m;
        char *r;
        char *val;

        val = strdup("my val");
        assert_se(val);

        m = hashmap_new(string_hash_func, string_compare_func);

        hashmap_put(m, "Key 1", val);

        r = hashmap_get(m, "Key 1");
        assert_se(streq(r, val));

        assert_se(m);
        hashmap_free_free(m);
}

static void test_hashmap_many(void) {
        Hashmap *h;
        unsigned i;

#define N_ENTRIES 100000

        assert_se(h = hashmap_new(NULL, NULL));

        for (i = 1; i < N_ENTRIES*3; i+=3) {
                assert_se(hashmap_put(h, UINT_TO_PTR(i), UINT_TO_PTR(i)) >= 0);
                assert_se(PTR_TO_UINT(hashmap_get(h, UINT_TO_PTR(i))) == i);
        }

        for (i = 1; i < N_ENTRIES*3; i++)
                assert_se(hashmap_contains(h, UINT_TO_PTR(i)) == (i % 3 == 1));

        log_info("%u <= %u * 0.75 = %g", hashmap_size(h), hashmap_buckets(h), hashmap_buckets(h) * 0.75);

        assert_se(hashmap_size(h) <= hashmap_buckets(h) * 0.75);
        assert_se(hashmap_size(h) == N_ENTRIES);

        hashmap_free(h);
}

static void test_hashmap_first_key(void) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        m = hashmap_new(string_hash_func, string_compare_func);
        assert_se(m);

        assert_se(!hashmap_first_key(m));
        assert_se(hashmap_put(m, "key 1", NULL) == 1);
        assert_se(streq(hashmap_first_key(m), "key 1"));
        assert_se(hashmap_put(m, "key 2", NULL) == 1);
        assert_se(streq(hashmap_first_key(m), "key 1"));
        assert_se(hashmap_remove(m, "key 1") == NULL);
        assert_se(streq(hashmap_first_key(m), "key 2"));
}

static void test_hashmap_last(void) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        m = hashmap_new(string_hash_func, string_compare_func);
        assert_se(m);

        assert_se(!hashmap_last(m));
        assert_se(hashmap_put(m, "key 1", (void *) (const char *) "val 1") == 1);
        assert_se(streq(hashmap_last(m), "val 1"));
        assert_se(hashmap_put(m, "key 2", (void *) (const char *) "bar") == 1);
        assert_se(streq(hashmap_last(m), "bar"));
        assert_se(hashmap_remove(m, "key 2"));
        assert_se(streq(hashmap_last(m), "val 1"));
}

static void test_hashmap_steal_first_key(void) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        m = hashmap_new(string_hash_func, string_compare_func);
        assert_se(m);

        assert_se(!hashmap_steal_first_key(m));
        assert_se(hashmap_put(m, "key 1", NULL) == 1);
        assert_se(streq(hashmap_steal_first_key(m), "key 1"));

        assert_se(hashmap_isempty(m));
}

static void test_hashmap_clear_free_free(void) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        m = hashmap_new(string_hash_func, string_compare_func);
        assert_se(m);

        assert_se(hashmap_put(m, strdup("key 1"), NULL) == 1);
        assert_se(hashmap_put(m, strdup("key 2"), NULL) == 1);
        assert_se(hashmap_put(m, strdup("key 3"), NULL) == 1);

        hashmap_clear_free_free(m);
        assert_se(hashmap_isempty(m));
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
        assert_se(!string_compare_func("fred", "wilma") == 0);
        assert_se(string_compare_func("fred", "fred") == 0);
}

int main(int argc, const char *argv[]) {
        test_hashmap_copy();
        test_hashmap_get_strv();
        test_hashmap_move_one();
        test_hashmap_next();
        test_hashmap_replace();
        test_hashmap_update();
        test_hashmap_put();
        test_hashmap_remove_and_put();
        test_hashmap_ensure_allocated();
        test_hashmap_foreach();
        test_hashmap_foreach_backwards();
        test_hashmap_foreach_key();
        test_hashmap_contains();
        test_hashmap_merge();
        test_hashmap_isempty();
        test_hashmap_get();
        test_hashmap_size();
        test_hashmap_many();
        test_hashmap_first_key();
        test_hashmap_last();
        test_hashmap_steal_first_key();
        test_hashmap_clear_free_free();
        test_uint64_compare_func();
        test_trivial_compare_func();
        test_string_compare_func();
}
