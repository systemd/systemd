/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "memory-util.h"
#include "tests.h"

TEST(iovec_shift) {
        const struct iovec iov = CONST_IOVEC_MAKE_STRING("54321");

        ASSERT_EQ(iovec_memcmp(&IOVEC_SHIFT(&iov, 0), &CONST_IOVEC_MAKE_STRING("54321")), 0);
        ASSERT_EQ(iovec_memcmp(&IOVEC_SHIFT(&iov, 1), &CONST_IOVEC_MAKE_STRING("4321")), 0);
        ASSERT_EQ(iovec_memcmp(&IOVEC_SHIFT(&iov, 2), &CONST_IOVEC_MAKE_STRING("321")), 0);
        ASSERT_EQ(iovec_memcmp(&IOVEC_SHIFT(&iov, 3), &CONST_IOVEC_MAKE_STRING("21")), 0);
        ASSERT_EQ(iovec_memcmp(&IOVEC_SHIFT(&iov, 4), &CONST_IOVEC_MAKE_STRING("1")), 0);
        ASSERT_FALSE(iovec_is_set(&IOVEC_SHIFT(&iov, 5)));
        ASSERT_FALSE(iovec_is_set(&IOVEC_SHIFT(&iov, 6)));
        ASSERT_FALSE(iovec_is_set(&IOVEC_SHIFT(&iov, 7)));

        const struct iovec empty = {};
        ASSERT_FALSE(iovec_is_set(&IOVEC_SHIFT(&empty, 0)));
        ASSERT_FALSE(iovec_is_set(&IOVEC_SHIFT(&empty, 1)));
}

TEST(iovec_inc) {
        struct iovec iov = IOVEC_MAKE_STRING("54321");

        ASSERT_EQ(iovec_memcmp(iovec_inc(&iov, 0), &CONST_IOVEC_MAKE_STRING("54321")), 0);
        ASSERT_EQ(iovec_memcmp(iovec_inc(&iov, 1), &CONST_IOVEC_MAKE_STRING("4321")), 0);
        ASSERT_EQ(iovec_memcmp(iovec_inc(&iov, 1), &CONST_IOVEC_MAKE_STRING("321")), 0);
        ASSERT_EQ(iovec_memcmp(iovec_inc(&iov, 1), &CONST_IOVEC_MAKE_STRING("21")), 0);
        ASSERT_EQ(iovec_memcmp(iovec_inc(&iov, 1), &CONST_IOVEC_MAKE_STRING("1")), 0);
        ASSERT_FALSE(iovec_is_set(iovec_inc(&iov, 1)));
        ASSERT_FALSE(iovec_is_set(iovec_inc(&iov, 1)));
        ASSERT_FALSE(iovec_is_set(iovec_inc(&iov, 1)));

        struct iovec empty = {};
        ASSERT_FALSE(iovec_is_set(iovec_inc(&empty, 0)));
        ASSERT_FALSE(iovec_is_set(iovec_inc(&empty, 1)));
}

TEST(iovec_inc_many) {
        ASSERT_TRUE(iovec_inc_many(NULL, 0, 0));
        ASSERT_TRUE(iovec_inc_many(&(struct iovec) {}, 0, 0));
        ASSERT_TRUE(iovec_inc_many(&(struct iovec) {}, 1, 0));

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("aaa")));
        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("bbb")));
        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("ccc")));

        ASSERT_FALSE(iovec_inc_many(iovw.iovec, iovw.count, 0));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[0], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("ccc")));

        ASSERT_FALSE(iovec_inc_many(iovw.iovec, iovw.count, 1));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[0], &IOVEC_MAKE_STRING("aa")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("ccc")));

        ASSERT_FALSE(iovec_inc_many(iovw.iovec, iovw.count, 3));
        ASSERT_FALSE(iovec_is_set(&iovw.iovec[0]));
        ASSERT_NULL(iovw.iovec[0].iov_base);
        ASSERT_EQ(iovw.iovec[0].iov_len, 0u);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &IOVEC_MAKE_STRING("bb")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("ccc")));

        ASSERT_FALSE(iovec_inc_many(iovw.iovec, iovw.count, 4));
        ASSERT_NULL(iovw.iovec[0].iov_base);
        ASSERT_EQ(iovw.iovec[0].iov_len, 0u);
        ASSERT_NULL(iovw.iovec[1].iov_base);
        ASSERT_EQ(iovw.iovec[1].iov_len, 0u);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("c")));

        ASSERT_TRUE(iovec_inc_many(iovw.iovec, iovw.count, 1));
        ASSERT_NULL(iovw.iovec[0].iov_base);
        ASSERT_EQ(iovw.iovec[0].iov_len, 0u);
        ASSERT_NULL(iovw.iovec[1].iov_base);
        ASSERT_EQ(iovw.iovec[1].iov_len, 0u);
        ASSERT_NULL(iovw.iovec[2].iov_base);
        ASSERT_EQ(iovw.iovec[2].iov_len, 0u);

        ASSERT_TRUE(iovec_inc_many(iovw.iovec, iovw.count, 0));
        ASSERT_NULL(iovw.iovec[0].iov_base);
        ASSERT_EQ(iovw.iovec[0].iov_len, 0u);
        ASSERT_NULL(iovw.iovec[1].iov_base);
        ASSERT_EQ(iovw.iovec[1].iov_len, 0u);
        ASSERT_NULL(iovw.iovec[2].iov_base);
        ASSERT_EQ(iovw.iovec[2].iov_len, 0u);

        ASSERT_SIGNAL(iovec_inc_many(iovw.iovec, iovw.count, 1), SIGABRT);
}

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

TEST(iovec_make_byte) {
        struct iovec x = IOVEC_MAKE_BYTE('x');

        ASSERT_EQ(x.iov_len, 1U);
        ASSERT_EQ(memcmp_nn(x.iov_base, x.iov_len, "x", 1), 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
