/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "journald-rate-limit.h"
#include "tests.h"
#include "time-util.h"

TEST(journal_ratelimit_test) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *rl = NULL;

        for (unsigned i = 0; i < 20; i++) {
                ASSERT_OK_EQ(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                             i < 10);
                ASSERT_OK_EQ(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                             i < 10);
        }

        /* Different priority group with the same ID is not ratelimited. */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_INFO, /* available= */ 0),
                     1);
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_INFO, /* available= */ 0),
                     1);
        /* Still LOG_DEBUG is ratelimited. */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     0);
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     0);
        /* Different ID is not ratelimited. */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "quux", USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     1);

        usleep_safe(USEC_PER_SEC);

        /* The ratelimit is now expired (11 trials are suppressed, so the return value should be 12). */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     1 + 11);

        /* foo is still ratelimited. */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     0);

        /* Still other priority and/or other IDs are not ratelimited. */
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_INFO, /* available= */ 0),
                     1);
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_INFO, /* available= */ 0),
                     1);
        ASSERT_OK_EQ(journal_ratelimit_test(&rl, "quux", USEC_PER_SEC, 10, LOG_DEBUG, /* available= */ 0),
                     1);
}

DEFINE_TEST_MAIN(LOG_INFO);
