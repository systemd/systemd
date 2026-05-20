/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "log.h"
#include "memory-util.h"
#include "random-util.h"
#include "terminal-util.h"
#include "tests.h"

TEST(random_bytes) {
        uint8_t buf[16] = {};

        for (size_t i = 1; i < sizeof buf; i++) {
                random_bytes(buf, i);
                if (i + 1 < sizeof buf)
                        ASSERT_EQ(buf[i], 0);

                hexdump(stdout, buf, i);
        }
}

TEST(crypto_random_bytes) {
        uint8_t buf[16] = {};

        for (size_t i = 1; i < sizeof buf; i++) {
                ASSERT_OK(crypto_random_bytes(buf, i));
                if (i + 1 < sizeof buf)
                        ASSERT_EQ(buf[i], 0);

                hexdump(stdout, buf, i);
        }
}

#define TOTAL 100000

static void test_random_u64_range_one(unsigned mod) {
        log_info("/* %s(%u) */", __func__, mod);

        unsigned max = 0, count[mod];
        zero(count);

        for (unsigned i = 0; i < TOTAL; i++) {
                uint64_t x;

                x = random_u64_range(mod);

                count[x]++;
                max = MAX(max, count[x]);
        }

        /* Print histogram: vertical axis — value, horizontal axis — count.
         *
         * The expected value is always TOTAL/mod, because the distribution should be flat. The expected
         * variance is TOTAL×p×(1-p), where p==1/mod. Assert that the deviation from the expected value
         * is less than 6 standard deviations by comparing squared values (diff² < 36·variance), which
         * avoids a sqrt() call and the libm dependency that comes with it at -O0.
         */
        unsigned scale = 2 * max / (columns() < 20 ? 80 : columns() - 20);
        double exp = (double) TOTAL / mod;
        double variance = exp * (mod > 1 ? mod - 1 : 1) / mod;

        for (size_t i = 0; i < mod; i++) {
                double diff = count[i] - exp;
                double dev_sq = diff * diff / variance;

                log_debug("%02zu: %5u (z²=%.3f)%*s",
                          i, count[i], dev_sq,
                          (int) (count[i] / scale), "x");

                ASSERT_TRUE(dev_sq < 36); /* 36 = 6²; 6 sigma is excessive, but this check should be
                                           * enough to identify catastrophic failure while minimizing
                                           * false positives. */
        }
}

TEST(random_u64_range) {
        for (unsigned mod = 1; mod < 29; mod++)
                test_random_u64_range_one(mod);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
