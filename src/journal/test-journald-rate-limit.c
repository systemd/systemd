/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-rate-limit.h"
#include "tests.h"

TEST(journal_ratelimit_test) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *rl = NULL;
        int r;

        for (unsigned i = 0; i < 20; i++) {
                r = journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, 0);
                assert_se(r == (i < 10 ? 1 : 0));
                r = journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, 0);
                assert_se(r == (i < 10 ? 1 : 0));
        }

        /* Different priority group with the same ID is not ratelimited. */
        assert_se(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_INFO, 0) == 1);
        assert_se(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_INFO, 0) == 1);
        /* Still LOG_DEBUG is ratelimited. */
        assert_se(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, 0) == 0);
        assert_se(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, 0) == 0);
        /* Different ID is not ratelimited. */
        assert_se(journal_ratelimit_test(&rl, "quux", USEC_PER_SEC, 10, LOG_DEBUG, 0) == 1);

        usleep_safe(USEC_PER_SEC);

        /* The ratelimit is now expired (11 trials are suppressed, so the return value should be 12). */
        assert_se(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_DEBUG, 0) == 1 + 11);

        /* foo is still ratelimited. */
        assert_se(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_DEBUG, 0) == 0);

        /* Still other priority and/or other IDs are not ratelimited. */
        assert_se(journal_ratelimit_test(&rl, "hoge", USEC_PER_SEC, 10, LOG_INFO, 0) == 1);
        assert_se(journal_ratelimit_test(&rl, "foo", 10 * USEC_PER_SEC, 10, LOG_INFO, 0) == 1);
        assert_se(journal_ratelimit_test(&rl, "quux", USEC_PER_SEC, 10, LOG_DEBUG, 0) == 1);
}

DEFINE_TEST_MAIN(LOG_INFO);
