/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "limits-util.h"
#include "tests.h"

TEST(physical_memory) {
        uint64_t p;

        p = physical_memory();
        ASSERT_GT(p, 0U);
        ASSERT_LT(p, UINT64_MAX);
        ASSERT_EQ(p % page_size(), 0U);

        log_info("Memory: %s (%" PRIu64 ")", FORMAT_BYTES(p), p);
}

TEST(physical_memory_scale) {
        uint64_t p;

        p = physical_memory();

        ASSERT_EQ(physical_memory_scale(0, 100), 0U);
        ASSERT_EQ(physical_memory_scale(100, 100), p);

        log_info("Memory original: %" PRIu64, physical_memory());
        log_info("Memory scaled by 50%%: %" PRIu64, physical_memory_scale(50, 100));
        log_info("Memory divided by 2: %" PRIu64, physical_memory() / 2);
        log_info("Page size: %zu", page_size());

        /* There might be an uneven number of pages, hence permit these calculations to be half a page off... */
        ASSERT_LE(page_size()/2 + physical_memory_scale(50, 100) - p/2, page_size());
        ASSERT_EQ(physical_memory_scale(200, 100), p*2);

        ASSERT_EQ(physical_memory_scale(0, 1), 0U);
        ASSERT_EQ(physical_memory_scale(1, 1), p);
        ASSERT_EQ(physical_memory_scale(2, 1), p*2);

        ASSERT_EQ(physical_memory_scale(0, 2), 0U);

        ASSERT_LE(page_size()/2 + physical_memory_scale(1, 2) - p/2, page_size());
        ASSERT_EQ(physical_memory_scale(2, 2), p);
        ASSERT_EQ(physical_memory_scale(4, 2), p*2);

        ASSERT_EQ(physical_memory_scale(0, UINT32_MAX), 0U);
        ASSERT_EQ(physical_memory_scale(UINT32_MAX, UINT32_MAX), p);

        /* overflow */
        ASSERT_EQ(physical_memory_scale(UINT64_MAX/4, UINT64_MAX), UINT64_MAX);
}

TEST(system_tasks_max) {
        uint64_t t;

        t = system_tasks_max();
        ASSERT_GT(t, 0U);
        ASSERT_LT(t, UINT64_MAX);

        log_info("Max tasks: %" PRIu64, t);
}

TEST(system_tasks_max_scale) {
        uint64_t t;

        t = system_tasks_max();

        ASSERT_EQ(system_tasks_max_scale(0, 100), 0U);
        ASSERT_EQ(system_tasks_max_scale(100, 100), t);

        ASSERT_EQ(system_tasks_max_scale(0, 1), 0U);
        ASSERT_EQ(system_tasks_max_scale(1, 1), t);
        ASSERT_EQ(system_tasks_max_scale(2, 1), 2*t);

        ASSERT_EQ(system_tasks_max_scale(0, 2), 0U);
        ASSERT_EQ(system_tasks_max_scale(1, 2), t/2);
        ASSERT_EQ(system_tasks_max_scale(2, 2), t);
        ASSERT_EQ(system_tasks_max_scale(3, 2), (3*t)/2);
        ASSERT_EQ(system_tasks_max_scale(4, 2), t*2);

        ASSERT_EQ(system_tasks_max_scale(0, UINT32_MAX), 0U);
        ASSERT_EQ(system_tasks_max_scale((UINT32_MAX-1)/2, UINT32_MAX-1), t/2);
        ASSERT_EQ(system_tasks_max_scale(UINT32_MAX, UINT32_MAX), t);

        /* overflow */

        ASSERT_EQ(system_tasks_max_scale(UINT64_MAX/4, UINT64_MAX), UINT64_MAX);
}

DEFINE_TEST_MAIN(LOG_INFO);
