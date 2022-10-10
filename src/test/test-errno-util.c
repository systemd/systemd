/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"

TEST(strerror_not_threadsafe) {
        /* Just check that strerror really is not thread-safe. */
        log_info("strerror(%d) → %s", 200, strerror(200));
        log_info("strerror(%d) → %s", 201, strerror(201));
        log_info("strerror(%d) → %s", INT_MAX, strerror(INT_MAX));

        log_info("strerror(%d), strerror(%d) → %p, %p", 200, 201, strerror(200), strerror(201));

        /* This call is not allowed, because the first returned string becomes invalid when
         * we call strerror the second time:
         *
         * log_info("strerror(%d), strerror(%d) → %s, %s", 200, 201, strerror(200), strerror(201));
         */
}

TEST(STRERROR) {
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

        const char *c = STRERROR(INT_MAX);
        char buf[DECIMAL_STR_MAX(int)];
        xsprintf(buf, "%d", INT_MAX);  /* INT_MAX is hexadecimal, use printf to convert to decimal */
        log_info("STRERROR(%d) → %s", INT_MAX, c);
        assert_se(strstr(c, buf));
}

TEST(STRERROR_OR_ELSE) {
        log_info("STRERROR_OR_ELSE(0, \"EOF\") → %s", STRERROR_OR_EOF(0));
        log_info("STRERROR_OR_ELSE(EPERM, \"EOF\") → %s", STRERROR_OR_EOF(EPERM));
        log_info("STRERROR_OR_ELSE(-EPERM, \"EOF\") → %s", STRERROR_OR_EOF(-EPERM));
}

DEFINE_TEST_MAIN(LOG_INFO);
