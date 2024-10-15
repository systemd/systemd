/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "tests.h"

TEST(iovec_memcmp) {
        struct iovec iov1 = CONST_IOVEC_MAKE_STRING("abcdef"), iov2 = IOVEC_MAKE_STRING("bcdefg"), empty = {};

        struct iovec iov1_truncated = iov1;
        iov1_truncated.iov_len /= 2;

        assert_se(iovec_memcmp(NULL, NULL) == 0);
        assert_se(iovec_memcmp(&iov1, &iov1) == 0);
        assert_se(iovec_memcmp(&iov2, &iov2) == 0);
        assert_se(iovec_memcmp(&empty, &empty) == 0);
        assert_se(iovec_memcmp(&iov1_truncated, &iov1_truncated) == 0);
        assert_se(iovec_memcmp(&empty, NULL) == 0);
        assert_se(iovec_memcmp(NULL, &empty) == 0);
        assert_se(iovec_memcmp(&iov1, &iov2) < 0);
        assert_se(iovec_memcmp(&iov2, &iov1) > 0);
        assert_se(iovec_memcmp(&iov1, &empty) > 0);
        assert_se(iovec_memcmp(&empty, &iov1) < 0);
        assert_se(iovec_memcmp(&iov2, &empty) > 0);
        assert_se(iovec_memcmp(&empty, &iov2) < 0);
        assert_se(iovec_memcmp(&iov1_truncated, &empty) > 0);
        assert_se(iovec_memcmp(&empty, &iov1_truncated) < 0);
        assert_se(iovec_memcmp(&iov1, &iov1_truncated) > 0);
        assert_se(iovec_memcmp(&iov1_truncated, &iov1) < 0);
        assert_se(iovec_memcmp(&iov2, &iov1_truncated) > 0);
        assert_se(iovec_memcmp(&iov1_truncated, &iov2) < 0);

        _cleanup_(iovec_done) struct iovec copy = {};

        assert_se(iovec_memdup(&iov1, &copy));
        assert_se(iovec_memcmp(&iov1, &copy) == 0);
}

TEST(iovec_set_and_valid) {
        struct iovec empty = {},
                filled = CONST_IOVEC_MAKE_STRING("waldo"),
                half = { .iov_base = (char*) "piff", .iov_len = 0 },
                invalid = { .iov_base = NULL, .iov_len = 47 };

        assert_se(!iovec_is_set(NULL));
        assert_se(!iovec_is_set(&empty));
        assert_se(iovec_is_set(&filled));
        assert_se(!iovec_is_set(&half));
        assert_se(!iovec_is_set(&invalid));

        assert_se(iovec_is_valid(NULL));
        assert_se(iovec_is_valid(&empty));
        assert_se(iovec_is_valid(&filled));
        assert_se(iovec_is_valid(&half));
        assert_se(!iovec_is_valid(&invalid));
}

TEST(iovec_append) {
        _cleanup_(iovec_done) struct iovec iov = {};

        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("")) == &iov);
        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("waldo")) == &iov);
        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("quux")) == &iov);
        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("")) == &iov);
        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("p")) == &iov);
        assert_se(iovec_append(&iov, &IOVEC_MAKE_STRING("")) == &iov);

        assert_se(iovec_memcmp(&iov, &IOVEC_MAKE_STRING("waldoquuxp")) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
