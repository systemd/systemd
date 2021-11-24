/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup.h"
#include "log.h"
#include "tests.h"

TEST(group_cpu_adjust_period) {
        /* Period 1ms, quota 40% -> Period 2.5ms */
        assert_se(2500 == cgroup_cpu_adjust_period(USEC_PER_MSEC, 400 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 10ms, quota 10% -> keep. */
        assert_se(10 * USEC_PER_MSEC == cgroup_cpu_adjust_period(10 * USEC_PER_MSEC, 100 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 1ms, quota 1000% -> keep. */
        assert_se(USEC_PER_MSEC == cgroup_cpu_adjust_period(USEC_PER_MSEC, 10000 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 100ms, quota 30% -> keep. */
        assert_se(100 * USEC_PER_MSEC == cgroup_cpu_adjust_period(100 * USEC_PER_MSEC, 300 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 5s, quota 40% -> adjust to 1s. */
        assert_se(USEC_PER_SEC == cgroup_cpu_adjust_period(5 * USEC_PER_SEC, 400 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 2s, quota 250% -> adjust to 1s. */
        assert_se(USEC_PER_SEC == cgroup_cpu_adjust_period(2 * USEC_PER_SEC, 2500 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 10us, quota 5,000,000% -> adjust to 1ms. */
        assert_se(USEC_PER_MSEC == cgroup_cpu_adjust_period(10, 50000000 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 10ms, quota 50,000% -> keep. */
        assert_se(10 * USEC_PER_MSEC == cgroup_cpu_adjust_period(10 * USEC_PER_MSEC, 500000 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 10ms, quota 1% -> adjust to 100ms. */
        assert_se(100 * USEC_PER_MSEC == cgroup_cpu_adjust_period(10 * USEC_PER_MSEC, 10 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 10ms, quota .001% -> adjust to 1s. */
        assert_se(1 * USEC_PER_SEC == cgroup_cpu_adjust_period(10 * USEC_PER_MSEC, 10, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 0ms, quota 200% -> adjust to 1ms. */
        assert_se(1 * USEC_PER_MSEC == cgroup_cpu_adjust_period(0, 2 * USEC_PER_SEC, USEC_PER_MSEC, USEC_PER_SEC));
        /* Period 0ms, quota 40% -> adjust to 2.5ms. */
        assert_se(2500 == cgroup_cpu_adjust_period(0, 400 * USEC_PER_MSEC, USEC_PER_MSEC, USEC_PER_SEC));
}

DEFINE_TEST_MAIN(LOG_INFO);
