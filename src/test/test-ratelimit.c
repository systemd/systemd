/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "macro.h"
#include "ratelimit.h"
#include "tests.h"
#include "time-util.h"

TEST(ratelimit_below) {
        int i;
        RateLimit ratelimit = { 1 * USEC_PER_SEC, 10 };

        for (i = 0; i < 10; i++)
                assert_se(ratelimit_below(&ratelimit));
        assert_se(!ratelimit_below(&ratelimit));
        sleep(1);
        for (i = 0; i < 10; i++)
                assert_se(ratelimit_below(&ratelimit));

        ratelimit = (RateLimit) { 0, 10 };
        for (i = 0; i < 10000; i++)
                assert_se(ratelimit_below(&ratelimit));
}

TEST(ratelimit_num_dropped) {
        int i;
        RateLimit ratelimit = { 1 * USEC_PER_SEC, 10 };

        for (i = 0; i < 10; i++) {
                assert_se(ratelimit_below(&ratelimit));
                assert_se(ratelimit_num_dropped(&ratelimit) == 0);
        }
        assert_se(!ratelimit_below(&ratelimit));
        assert_se(ratelimit_num_dropped(&ratelimit) == 1);
        assert_se(!ratelimit_below(&ratelimit));
        assert_se(ratelimit_num_dropped(&ratelimit) == 2);
        sleep(1);
        assert_se(ratelimit_below(&ratelimit));
        assert_se(ratelimit_num_dropped(&ratelimit) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
