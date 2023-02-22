/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util.h"
#include "tests.h"

TEST(eqzero) {
        const uint32_t zeros[] = {0, 0, 0};
        const uint32_t ones[] = {1, 1};
        const uint32_t mixed[] = {0, 1, 0, 0, 0};
        const uint8_t longer[] = {[55] = 255};

        assert_se(eqzero(zeros));
        assert_se(!eqzero(ones));
        assert_se(!eqzero(mixed));
        assert_se(!eqzero(longer));
}

static void my_destructor(struct iovec *iov, size_t n) {
        /* not really a destructor, just something we can use to check if the destruction worked */
        memset(iov, 'y', sizeof(struct iovec) * n);
}

TEST(cleanup_array) {
        struct iovec *iov, *saved_iov;
        size_t n, saved_n;

        n = 7;
        iov = new(struct iovec, n);
        assert_se(iov);

        memset(iov, 'x', sizeof(struct iovec) * n);

        saved_iov = iov;
        saved_n = n;

        {
                assert_se(memeqbyte('x', saved_iov, sizeof(struct iovec) * saved_n));
                assert_se(iov);
                assert_se(n > 0);

                CLEANUP_ARRAY(iov, n, my_destructor);

                assert_se(memeqbyte('x', saved_iov, sizeof(struct iovec) * saved_n));
                assert_se(iov);
                assert_se(n > 0);
        }

        assert_se(memeqbyte('y', saved_iov, sizeof(struct iovec) * saved_n));
        assert_se(!iov);
        assert_se(n == 0);

        free(saved_iov);
}

DEFINE_TEST_MAIN(LOG_INFO);
