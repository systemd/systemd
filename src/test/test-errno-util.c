/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "macro.h"
#include "stdio-util.h"
#include "tests.h"

TEST(strerror_not_threadsafe) {
        /* Just check that strerror really is not thread-safe. */
        log_info("strerror(%d) → %s", 200, strerror(200));              /* NOLINT(bugprone-unsafe-functions) */
        log_info("strerror(%d) → %s", 201, strerror(201));              /* NOLINT(bugprone-unsafe-functions) */
        log_info("strerror(%d) → %s", INT_MAX, strerror(INT_MAX));      /* NOLINT(bugprone-unsafe-functions) */

        /* NOLINTNEXTLINE(bugprone-unsafe-functions) */
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
        ASSERT_NOT_NULL(strstr(a, "200"));
        ASSERT_NOT_NULL(strstr(b, "201"));

        /* Check with negative values */
        ASSERT_STREQ(a, STRERROR(-200));
        ASSERT_STREQ(b, STRERROR(-201));

        const char *c = STRERROR(INT_MAX);
        char buf[DECIMAL_STR_MAX(int)];
        xsprintf(buf, "%d", INT_MAX);  /* INT_MAX is hexadecimal, use printf to convert to decimal */
        log_info("STRERROR(%d) → %s", INT_MAX, c);
        ASSERT_NOT_NULL(strstr(c, buf));
}

TEST(STRERROR_OR_EOF) {
        log_info("STRERROR_OR_EOF(0, \"EOF\") → %s", STRERROR_OR_EOF(0));
        log_info("STRERROR_OR_EOF(EPERM, \"EOF\") → %s", STRERROR_OR_EOF(EPERM));
        log_info("STRERROR_OR_EOF(-EPERM, \"EOF\") → %s", STRERROR_OR_EOF(-EPERM));
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

TEST(ERR_TO_PTR) {
        /* Basic roundtrip with positive errno values */
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(EINVAL)), -EINVAL);
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(ENOMEM)), -ENOMEM);
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(ENOENT)), -ENOENT);

        /* ABS() handles negative values too */
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(-EINVAL)), -EINVAL);
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(-ENOMEM)), -ENOMEM);

        /* Edge cases */
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(1)), -1);
        ASSERT_EQ(PTR_TO_ERR(ERR_TO_PTR(ERRNO_MAX)), -ERRNO_MAX);

        /* PTR_IS_ERR detection */
        ASSERT_TRUE(PTR_IS_ERR(ERR_TO_PTR(EINVAL)));
        ASSERT_TRUE(PTR_IS_ERR(ERR_TO_PTR(1)));
        ASSERT_TRUE(PTR_IS_ERR(ERR_TO_PTR(ERRNO_MAX)));

        /* PTR_IS_ERR rejects non-errors */
        ASSERT_FALSE(PTR_IS_ERR(NULL));
        ASSERT_FALSE(PTR_IS_ERR(POINTER_MAX));
        ASSERT_FALSE(PTR_IS_ERR(INT_TO_PTR(1)));
        ASSERT_FALSE(PTR_IS_ERR(INT_TO_PTR(4096)));

        /* PTR_IS_ERR_OR_NULL */
        ASSERT_TRUE(PTR_IS_ERR_OR_NULL(NULL));
        ASSERT_TRUE(PTR_IS_ERR_OR_NULL(ERR_TO_PTR(EINVAL)));
        ASSERT_FALSE(PTR_IS_ERR_OR_NULL(INT_TO_PTR(1)));
        ASSERT_FALSE(PTR_IS_ERR_OR_NULL(POINTER_MAX));

        /* PTR_TO_ERR_OR_ZERO */
        ASSERT_EQ(PTR_TO_ERR_OR_ZERO(ERR_TO_PTR(EINVAL)), -EINVAL);
        ASSERT_EQ(PTR_TO_ERR_OR_ZERO(INT_TO_PTR(1)), 0);

        /* Does not conflict with POINTER_MAX sentinel */
        ASSERT_TRUE(ERR_TO_PTR(1) != POINTER_MAX);
}

DEFINE_TEST_MAIN(LOG_INFO);
