/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "ratelimit.h"
#include "tests.h"
#include "time-util.h"

TEST(ratelimit_below) {
        int i;
        RateLimit ratelimit = { 1 * USEC_PER_SEC, 10 };

        for (i = 0; i < 10; i++)
                ASSERT_TRUE(ratelimit_below(&ratelimit));
        ASSERT_FALSE(ratelimit_below(&ratelimit));
        sleep(1);
        for (i = 0; i < 10; i++)
                ASSERT_TRUE(ratelimit_below(&ratelimit));

        ratelimit = (const RateLimit) { 0, 10 };
        for (i = 0; i < 10000; i++)
                ASSERT_TRUE(ratelimit_below(&ratelimit));
}

TEST(ratelimit_num_dropped) {
        int i;
        RateLimit ratelimit = { 1 * USEC_PER_SEC, 10 };

        for (i = 0; i < 10; i++) {
                ASSERT_TRUE(ratelimit_below(&ratelimit));
                ASSERT_EQ(ratelimit_num_dropped(&ratelimit), 0U);
        }
        ASSERT_FALSE(ratelimit_below(&ratelimit));
        ASSERT_EQ(ratelimit_num_dropped(&ratelimit), 1U);
        ASSERT_FALSE(ratelimit_below(&ratelimit));
        ASSERT_EQ(ratelimit_num_dropped(&ratelimit), 2U);
        sleep(1);
        ASSERT_TRUE(ratelimit_below(&ratelimit));
        ASSERT_EQ(ratelimit_num_dropped(&ratelimit), 0U);
}

DEFINE_TEST_MAIN(LOG_INFO);
