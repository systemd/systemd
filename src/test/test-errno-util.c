/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "string-util.h"
#include "tests.h"

TEST(test_strerror_not_threadsafe) {
        /* Just check that strerror really is not thread-safe. */
        log_info("strerror(%d) → %s", 200, strerror(200));  /* lgtm [cpp/potentially-dangerous-function] */
        log_info("strerror(%d) → %s", 201, strerror(201));  /* lgtm [cpp/potentially-dangerous-function] */

        /* The same static buffer is used for both, so we expect the same string for both 200 and 201. */
        log_info("strerror(%d), strerror(%d) → %s, %s", 200, 201, strerror(200), strerror(201));  /* lgtm [cpp/potentially-dangerous-function] */
}

TEST(test_STRERROR) {
        /* Just check that STRERROR really is thread-safe. */
        log_info("STRERROR(%d) → %s", 200, STRERROR(200));
        log_info("STRERROR(%d) → %s", 201, STRERROR(201));
        log_info("STRERROR(%d), STRERROR(%d) → %s, %s", 200, 201, STRERROR(200), STRERROR(201));

        const char *a = STRERROR(200), *b = STRERROR(201);
        assert_se(strstr(a, "200"));
        assert_se(strstr(b, "201"));

        /* Check with negative values */
        assert_se(streq(a, STRERROR(-200)));
        assert_se(streq(b, STRERROR(-201)));
}

DEFINE_TEST_MAIN(LOG_INFO);
