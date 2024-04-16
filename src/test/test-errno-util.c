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
        ASSERT_STREQ(a, STRERROR(-200));
        ASSERT_STREQ(b, STRERROR(-201));

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

TEST(PROTECT_ERRNO) {
        errno = 12;
        {
                PROTECT_ERRNO;
                errno = 11;
        }
        assert_se(errno == 12);
}

static void test_unprotect_errno_inner_function(void) {
        PROTECT_ERRNO;

        errno = 2222;
}

TEST(UNPROTECT_ERRNO) {
        errno = 4711;

        PROTECT_ERRNO;

        errno = 815;

        UNPROTECT_ERRNO;

        assert_se(errno == 4711);

        test_unprotect_errno_inner_function();

        assert_se(errno == 4711);
}

TEST(RET_GATHER) {
        int x = 0, y = 2;

        assert_se(RET_GATHER(x, 5) == 0);
        assert_se(RET_GATHER(x, -5) == -5);
        assert_se(RET_GATHER(x, -1) == -5);

        assert_se(RET_GATHER(x, y++) == -5);
        assert_se(y == 3);
}

TEST(ERRNO_IS_TRANSIENT) {
        assert_se( ERRNO_IS_NEG_TRANSIENT(-EINTR));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(EINTR));
        assert_se( ERRNO_IS_TRANSIENT(-EINTR));
        assert_se( ERRNO_IS_TRANSIENT(EINTR));

        /* Test with type wider than int */
        ssize_t r = -EAGAIN;
        assert_se( ERRNO_IS_NEG_TRANSIENT(r));

        /* On 64-bit arches, now (int) r == EAGAIN */
        r = SSIZE_MAX - EAGAIN + 1;
        assert_se(!ERRNO_IS_NEG_TRANSIENT(r));

        assert_se(!ERRNO_IS_NEG_TRANSIENT(INT_MAX));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(INT_MIN));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(INTMAX_MAX));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(INTMAX_MIN));
}

DEFINE_TEST_MAIN(LOG_INFO);
