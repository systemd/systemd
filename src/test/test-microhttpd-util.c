/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "microhttpd-util.h"
#include "tests.h"
#include "time-util.h"

TEST(mhd_timeout_to_deadline) {
        const usec_t n = 1234567;
        const uint64_t last = (USEC_INFINITY - n) / USEC_PER_MSEC;

        ASSERT_EQ(mhd_timeout_to_deadline(n, 0), n);
        ASSERT_EQ(mhd_timeout_to_deadline(n, 1), n + USEC_PER_MSEC);
        ASSERT_EQ(mhd_timeout_to_deadline(n, 30000), n + 30 * USEC_PER_SEC);
        ASSERT_EQ(mhd_timeout_to_deadline(n, last), n + last * USEC_PER_MSEC);
        ASSERT_EQ(mhd_timeout_to_deadline(n, last + 1), USEC_INFINITY);
        ASSERT_EQ(mhd_timeout_to_deadline(n, UINT64_MAX), USEC_INFINITY);
        ASSERT_EQ(mhd_timeout_to_deadline(USEC_INFINITY, 0), USEC_INFINITY);
        ASSERT_EQ(mhd_timeout_to_deadline(USEC_INFINITY - 1, 1), USEC_INFINITY);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
