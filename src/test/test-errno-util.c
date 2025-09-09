/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "stdio-util.h"
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
#ifdef __GLIBC__
        ASSERT_NOT_NULL(strstr(a, "200"));
        ASSERT_NOT_NULL(strstr(b, "201"));
#else
        /* musl provides catch all error message for unknown error number. */
        ASSERT_STREQ(a, "No error information");
        ASSERT_STREQ(b, "No error information");
#endif

        /* Check with negative values */
        ASSERT_STREQ(a, STRERROR(-200));
        ASSERT_STREQ(b, STRERROR(-201));

        const char *c = STRERROR(INT_MAX);
        log_info("STRERROR(%d) → %s", INT_MAX, c);
#ifdef __GLIBC__
        char buf[DECIMAL_STR_MAX(int)];
        xsprintf(buf, "%d", INT_MAX);  /* INT_MAX is hexadecimal, use printf to convert to decimal */
        ASSERT_NOT_NULL(strstr(c, buf));
#else
        ASSERT_STREQ(c, "No error information");
#endif
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
        ASSERT_EQ(errno, 12);
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

        ASSERT_EQ(errno, 4711);

        test_unprotect_errno_inner_function();
        ASSERT_EQ(errno, 4711);
}

TEST(RET_GATHER) {
        int x = 0, y = 2;

        ASSERT_EQ(RET_GATHER(x, 5), 0);
        ASSERT_EQ(RET_GATHER(x, -5), -5);
        ASSERT_EQ(RET_GATHER(x, -1), -5);

        ASSERT_EQ(RET_GATHER(x, y++), -5);
        ASSERT_EQ(y, 3);
}

TEST(ERRNO_IS_TRANSIENT) {
        ASSERT_TRUE(ERRNO_IS_NEG_TRANSIENT(-EINTR));
        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(EINTR));
        ASSERT_TRUE(ERRNO_IS_TRANSIENT(-EINTR));
        ASSERT_TRUE(ERRNO_IS_TRANSIENT(EINTR));

        /* Test with type wider than int */
        ssize_t r = -EAGAIN;
        ASSERT_TRUE(ERRNO_IS_NEG_TRANSIENT(r));

        /* On 64-bit arches, now (int) r == EAGAIN */
        r = SSIZE_MAX - EAGAIN + 1;
        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(r));

        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(INT_MAX));
        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(INT_MIN));
        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(INTMAX_MAX));
        ASSERT_FALSE(ERRNO_IS_NEG_TRANSIENT(INTMAX_MIN));
}

DEFINE_TEST_MAIN(LOG_INFO);
