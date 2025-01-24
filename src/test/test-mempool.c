/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mempool.h"
#include "random-util.h"
#include "tests.h"

struct element {
        uint64_t value;
};

DEFINE_MEMPOOL(test_mempool, struct element, 8);

TEST(mempool_trim) {

#define NN 4000
        struct element *a[NN];
        size_t n_freed = 0;

        assert_se(!test_mempool.first_pool);
        assert_se(!test_mempool.freelist);

        mempool_trim(&test_mempool);

        for (size_t i = 0; i < NN; i++) {
                assert_se(a[i] = mempool_alloc_tile(&test_mempool));
                a[i]->value = i;
        }

        mempool_trim(&test_mempool);

        /* free up to one third randomly */
        size_t x = 0;
        for (size_t i = 0; i < NN/3; i++) {
                x = (x + random_u64()) % ELEMENTSOF(a);
                assert_se(!a[x] || a[x]->value == x);

                if (a[x])
                        n_freed++;

                a[x] = mempool_free_tile(&test_mempool, a[x]);
        }

        mempool_trim(&test_mempool);

        /* free definitely at least one third */
        for (size_t i = 2; i < NN; i += 3) {
                assert_se(!a[i] || a[i]->value == i);
                if (a[i])
                        n_freed++;
                a[i] = mempool_free_tile(&test_mempool, a[i]);
        }

        mempool_trim(&test_mempool);

        /* Allocate another set of tiles, which will fill up the free list and allocate some new tiles */
        struct element *b[NN];
        for (size_t i = 0; i < NN; i++) {
                assert_se(b[i] = mempool_alloc_tile(&test_mempool));
                b[i]->value = ~(uint64_t) i;
        }

        mempool_trim(&test_mempool);

        /* free everything from the original set */

        for (size_t i = 0; i < NN; i += 1) {
                assert_se(!a[i] || a[i]->value == i);
                if (a[i])
                        n_freed++;
                a[i] = mempool_free_tile(&test_mempool, a[i]);
        }

        mempool_trim(&test_mempool);

        /* and now everything from the second set too */

        for (size_t i = 0; i < NN; i += 1) {
                assert_se(!b[i] || b[i]->value == ~(uint64_t) i);
                if (b[i])
                        n_freed++;
                b[i] = mempool_free_tile(&test_mempool, b[i]);
        }

        assert_se(n_freed == NN * 2);

        mempool_trim(&test_mempool);

        assert_se(!test_mempool.first_pool);
        assert_se(!test_mempool.freelist);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
