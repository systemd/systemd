/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "prioq.h"
#include "set.h"
#include "siphash24.h"
#include "sort-util.h"
#include "tests.h"

#define SET_SIZE 1024*4

static int unsigned_compare(const unsigned *a, const unsigned *b) {
        return CMP(*a, *b);
}

TEST(unsigned) {
        _cleanup_(prioq_freep) Prioq *q = NULL;
        unsigned buffer[SET_SIZE], u, n;

        srand(0);

        assert_se(q = prioq_new(trivial_compare_func));

        FOREACH_ELEMENT(i, buffer) {
                u = (unsigned) rand();
                *i = u;
                assert_se(prioq_put(q, UINT_TO_PTR(u), NULL) >= 0);

                n = prioq_size(q);
                assert_se(prioq_remove(q, UINT_TO_PTR(u), &n) == 0);
        }

        typesafe_qsort(buffer, ELEMENTSOF(buffer), unsigned_compare);

        for (unsigned i = 0; i < ELEMENTSOF(buffer); i++) {
                assert_se(prioq_size(q) == ELEMENTSOF(buffer) - i);

                u = PTR_TO_UINT(prioq_pop(q));
                assert_se(buffer[i] == u);
        }

        assert_se(prioq_isempty(q));
}

struct test {
        unsigned value;
        unsigned idx;
};

static int test_compare(const struct test *x, const struct test *y) {
        return CMP(x->value, y->value);
}

static void test_hash(const struct test *x, struct siphash *state) {
        siphash24_compress_typesafe(x->value, state);
}

DEFINE_PRIVATE_HASH_OPS(test_hash_ops, struct test, test_hash, test_compare);

TEST(struct) {
        _cleanup_(prioq_freep) Prioq *q = NULL;
        _cleanup_set_free_ Set *s = NULL;
        unsigned previous = 0, i;
        struct test *t;

        srand(0);

        assert_se(q = prioq_new((compare_func_t) test_compare));
        assert_se(s = set_new(&test_hash_ops));

        ASSERT_NULL(prioq_peek(q));
        ASSERT_NULL(prioq_peek_by_index(q, 0));
        ASSERT_NULL(prioq_peek_by_index(q, 1));
        ASSERT_NULL(prioq_peek_by_index(q, UINT_MAX));

        for (i = 0; i < SET_SIZE; i++) {
                assert_se(t = new0(struct test, 1));
                t->value = (unsigned) rand();

                assert_se(prioq_put(q, t, &t->idx) >= 0);

                if (i % 4 == 0)
                        assert_se(set_consume(s, t) >= 0);
        }

        for (i = 0; i < SET_SIZE; i++)
                assert_se(prioq_peek_by_index(q, i));
        ASSERT_NULL(prioq_peek_by_index(q, SET_SIZE));

        unsigned count = 0;
        PRIOQ_FOREACH_ITEM(q, t) {
                assert_se(t);
                count++;
        }
        assert_se(count == SET_SIZE);

        while ((t = set_steal_first(s))) {
                assert_se(prioq_remove(q, t, &t->idx) == 1);
                assert_se(prioq_remove(q, t, &t->idx) == 0);
                assert_se(prioq_remove(q, t, NULL) == 0);

                free(t);
        }

        for (i = 0; i < SET_SIZE * 3 / 4; i++) {
                assert_se(prioq_size(q) == (SET_SIZE * 3 / 4) - i);

                assert_se(t = prioq_pop(q));
                assert_se(prioq_remove(q, t, &t->idx) == 0);
                assert_se(prioq_remove(q, t, NULL) == 0);
                assert_se(previous <= t->value);

                previous = t->value;
                free(t);
        }

        assert_se(prioq_isempty(q));
        assert_se(set_isempty(s));
}

DEFINE_TEST_MAIN(LOG_INFO);
