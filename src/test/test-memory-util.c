/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/uio.h>

#include "memory-util.h"
#include "tests.h"

TEST(eqzero) {
        const uint32_t zeros[] = {0, 0, 0};
        const uint32_t ones[] = {1, 1};
        const uint32_t mixed[] = {0, 1, 0, 0, 0};
        const uint8_t longer[] = {[55] = 255};

        ASSERT_TRUE(eqzero(zeros));
        ASSERT_FALSE(eqzero(ones));
        ASSERT_FALSE(eqzero(mixed));
        ASSERT_FALSE(eqzero(longer));
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
        ASSERT_NOT_NULL(iov);

        memset(iov, 'x', sizeof(struct iovec) * n);

        saved_iov = iov;
        saved_n = n;

        {
                ASSERT_TRUE(memeqbyte('x', saved_iov, sizeof(struct iovec) * saved_n));
                ASSERT_NOT_NULL(iov);
                ASSERT_GT(n, 0U);

                CLEANUP_ARRAY(iov, n, my_destructor);

                ASSERT_TRUE(memeqbyte('x', saved_iov, sizeof(struct iovec) * saved_n));
                ASSERT_NOT_NULL(iov);
                ASSERT_GT(n, 0U);
        }

        ASSERT_TRUE(memeqbyte('y', saved_iov, sizeof(struct iovec) * saved_n));
        ASSERT_NULL(iov);
        ASSERT_EQ(n, 0U);

        free(saved_iov);
}

TEST(page_align) {
        ASSERT_EQ(PAGE_ALIGN(page_size() - 1), page_size());
        ASSERT_EQ(PAGE_ALIGN(page_size()    ), page_size());
        ASSERT_EQ(PAGE_ALIGN(page_size() + 1), page_size() * 2);
        ASSERT_EQ(PAGE_ALIGN(page_size() * 123 - 1), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN(page_size() * 123    ), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN(page_size() * 123 + 1), page_size() * 124);
        ASSERT_EQ(PAGE_ALIGN(SIZE_MAX - page_size() - 1), SIZE_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN(SIZE_MAX - page_size()    ), SIZE_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN(SIZE_MAX - page_size() + 1), SIZE_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN(SIZE_MAX - page_size() + 2), SIZE_MAX); /* overflow */
        ASSERT_EQ(PAGE_ALIGN(SIZE_MAX), SIZE_MAX); /* overflow */

        ASSERT_EQ(PAGE_ALIGN_U64(page_size() - 1), page_size());
        ASSERT_EQ(PAGE_ALIGN_U64(page_size()    ), page_size());
        ASSERT_EQ(PAGE_ALIGN_U64(page_size() + 1), page_size() * 2);
        ASSERT_EQ(PAGE_ALIGN_U64(page_size() * 123 - 1), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_U64(page_size() * 123    ), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_U64(page_size() * 123 + 1), page_size() * 124);
        ASSERT_EQ(PAGE_ALIGN_U64(UINT64_MAX - page_size() - 1), UINT64_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN_U64(UINT64_MAX - page_size()    ), UINT64_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN_U64(UINT64_MAX - page_size() + 1), UINT64_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN_U64(UINT64_MAX - page_size() + 2), UINT64_MAX); /* overflow */
        ASSERT_EQ(PAGE_ALIGN_U64(UINT64_MAX), UINT64_MAX); /* overflow */

        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size() - 1), 0U);
        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size()    ), page_size());
        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size() + 1), page_size());
        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size() * 123 - 1), page_size() * 122);
        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size() * 123    ), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_DOWN(page_size() * 123 + 1), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_DOWN(SIZE_MAX - page_size() - 1), SIZE_MAX - page_size() * 2 + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN(SIZE_MAX - page_size()    ), SIZE_MAX - page_size() * 2 + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN(SIZE_MAX - page_size() + 1), SIZE_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN(SIZE_MAX - page_size() + 2), SIZE_MAX - page_size() + 1);

        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size() - 1), 0U);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size()    ), page_size());
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size() + 1), page_size());
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size() * 123 - 1), page_size() * 122);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size() * 123    ), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(page_size() * 123 + 1), page_size() * 123);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(SIZE_MAX - page_size() - 1), SIZE_MAX - page_size() * 2 + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(SIZE_MAX - page_size()    ), SIZE_MAX - page_size() * 2 + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(SIZE_MAX - page_size() + 1), SIZE_MAX - page_size() + 1);
        ASSERT_EQ(PAGE_ALIGN_DOWN_U64(SIZE_MAX - page_size() + 2), SIZE_MAX - page_size() + 1);

        ASSERT_EQ(PAGE_OFFSET(page_size() - 1), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET(page_size()    ), 0U);
        ASSERT_EQ(PAGE_OFFSET(page_size() + 1), 1U);
        ASSERT_EQ(PAGE_OFFSET(page_size() * 123 - 1), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET(page_size() * 123    ), 0U);
        ASSERT_EQ(PAGE_OFFSET(page_size() * 123 + 1), 1U);
        ASSERT_EQ(PAGE_OFFSET(SIZE_MAX - page_size() - 1), page_size() - 2);
        ASSERT_EQ(PAGE_OFFSET(SIZE_MAX - page_size()    ), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET(SIZE_MAX - page_size() + 1), 0U);
        ASSERT_EQ(PAGE_OFFSET(SIZE_MAX - page_size() + 2), 1U);

        ASSERT_EQ(PAGE_OFFSET_U64(page_size() - 1), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET_U64(page_size()    ), 0U);
        ASSERT_EQ(PAGE_OFFSET_U64(page_size() + 1), 1U);
        ASSERT_EQ(PAGE_OFFSET_U64(page_size() * 123 - 1), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET_U64(page_size() * 123    ), 0U);
        ASSERT_EQ(PAGE_OFFSET_U64(page_size() * 123 + 1), 1U);
        ASSERT_EQ(PAGE_OFFSET_U64(UINT64_MAX - page_size() - 1), page_size() - 2);
        ASSERT_EQ(PAGE_OFFSET_U64(UINT64_MAX - page_size()    ), page_size() - 1);
        ASSERT_EQ(PAGE_OFFSET_U64(UINT64_MAX - page_size() + 1), 0U);
        ASSERT_EQ(PAGE_OFFSET_U64(UINT64_MAX - page_size() + 2), 1U);
}

DEFINE_TEST_MAIN(LOG_INFO);
