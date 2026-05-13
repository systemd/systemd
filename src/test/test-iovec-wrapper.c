/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/uio.h>

#include "alloc-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "random-util.h"
#include "tests.h"

TEST(iovw_compare) {
        _cleanup_(iovw_done) struct iovec_wrapper a1 = {}, a2 = {}, b = {}, c = {}, d = {}, e = {};

        ASSERT_OK(iovw_put(&a1, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&a1, (char*) "aaaaa", 5));

        ASSERT_OK(iovw_put(&a2, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&a2, (char*) "aaaaa", 5));

        ASSERT_OK(iovw_put(&b, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&b, (char*) "bbbbb", 5));

        ASSERT_OK(iovw_put(&c, (char*) "foo", 3));

        ASSERT_OK(iovw_put(&d, (char*) "fooaa", 5));
        ASSERT_OK(iovw_put(&d, (char*) "aaa", 3));

        ASSERT_EQ(iovw_compare(&a1, &a1), 0);
        ASSERT_EQ(iovw_compare(&a1, &a2), 0);
        ASSERT_EQ(iovw_compare(&a2, &a1), 0);
        ASSERT_LT(iovw_compare(&a1, &b), 0);
        ASSERT_GT(iovw_compare(&b, &a1), 0);
        ASSERT_EQ(iovw_compare(&b, &b), 0);
        ASSERT_GT(iovw_compare(&a1, &c), 0);
        ASSERT_LT(iovw_compare(&c, &a1), 0);
        ASSERT_EQ(iovw_compare(&c, &c), 0);
        ASSERT_LT(iovw_compare(&a1, &d), 0);
        ASSERT_GT(iovw_compare(&d, &a1), 0);
        ASSERT_EQ(iovw_compare(&d, &d), 0);
        ASSERT_GT(iovw_compare(&a1, &e), 0);
        ASSERT_LT(iovw_compare(&e, &a1), 0);
        ASSERT_EQ(iovw_compare(&e, &e), 0);
        ASSERT_GT(iovw_compare(&a1, NULL), 0);
        ASSERT_LT(iovw_compare(NULL, &a1), 0);
        ASSERT_EQ(iovw_compare(NULL, NULL), 0);

        ASSERT_TRUE(iovw_equal(&a1, &a1));
        ASSERT_TRUE(iovw_equal(&a1, &a2));
        ASSERT_TRUE(iovw_equal(&a2, &a1));
        ASSERT_FALSE(iovw_equal(&a1, &b));
        ASSERT_FALSE(iovw_equal(&b, &a1));
        ASSERT_TRUE(iovw_equal(&b, &b));
        ASSERT_FALSE(iovw_equal(&a1, &c));
        ASSERT_FALSE(iovw_equal(&c, &a1));
        ASSERT_TRUE(iovw_equal(&c, &c));
        ASSERT_FALSE(iovw_equal(&a1, &d));
        ASSERT_FALSE(iovw_equal(&d, &a1));
        ASSERT_TRUE(iovw_equal(&d, &d));
        ASSERT_FALSE(iovw_equal(&a1, &e));
        ASSERT_FALSE(iovw_equal(&e, &a1));
        ASSERT_TRUE(iovw_equal(&e, &e));
        ASSERT_FALSE(iovw_equal(&a1, NULL));
        ASSERT_FALSE(iovw_equal(NULL, &a1));
        ASSERT_TRUE(iovw_equal(NULL, NULL));
}

TEST(iovw_put) {
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};

        /* Zero-length insertions are no-ops and do not touch the data pointer */
        ASSERT_OK_ZERO(iovw_put(&iovw, NULL, 0));
        ASSERT_OK_ZERO(iovw_put(&iovw, (char*) "foo", 0));
        ASSERT_EQ(iovw.count, 0U);

        ASSERT_OK(iovw_put(&iovw, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&iovw, (char*) "barbar", 6));
        ASSERT_OK(iovw_put(&iovw, (char*) "q", 1));
        ASSERT_EQ(iovw.count, 3U);

        ASSERT_EQ(iovw.iovec[0].iov_len, 3U);
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "foo", 3), 0);
        ASSERT_EQ(iovw.iovec[1].iov_len, 6U);
        ASSERT_EQ(memcmp(iovw.iovec[1].iov_base, "barbar", 6), 0);
        ASSERT_EQ(iovw.iovec[2].iov_len, 1U);
        ASSERT_EQ(memcmp(iovw.iovec[2].iov_base, "q", 1), 0);

        ASSERT_OK(iovw_put_full(&iovw, /* accept_zero= */ false, NULL, 0));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_OK(iovw_put_full(&iovw, /* accept_zero= */ true, NULL, 0));
        ASSERT_EQ(iovw.count, 4U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[3], &(struct iovec) {}));
}

TEST(iovw_put_iov) {
        /* iovw_put_iov() does not copy the input, hence do not use iovw_done_free */
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_put_iov(&iovw, NULL));
        ASSERT_OK_ZERO(iovw_put_iov(&iovw, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 0U);

        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("aaa")));
        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("bbb")));
        ASSERT_OK(iovw_put_iov(&iovw, &IOVEC_MAKE_STRING("ccc")));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[0], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("ccc")));

        ASSERT_OK(iovw_put_iov_full(&iovw, /* accept_zero= */ false, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_OK(iovw_put_iov_full(&iovw, /* accept_zero= */ true, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 4U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[3], &(struct iovec) {}));
}

TEST(iovw_put_iovw) {
        _cleanup_(iovw_done) struct iovec_wrapper target = {}, source = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_put_iovw(&target, NULL));
        ASSERT_OK_ZERO(iovw_put_iovw(&target, &source));
        ASSERT_EQ(target.count, 0U);

        ASSERT_OK(iovw_put_iov(&source, &IOVEC_MAKE_STRING("aaa")));
        ASSERT_OK(iovw_put_iov(&source, &IOVEC_MAKE_STRING("bbb")));
        ASSERT_OK(iovw_put_iov(&source, &IOVEC_MAKE_STRING("ccc")));
        ASSERT_OK(iovw_put_iov_full(&source, /* accept_zero= */ true, &(struct iovec) {}));
        ASSERT_EQ(source.count, 4U);

        /* Pre-seed target with one entry to check that append adds on top rather than replacing */
        ASSERT_OK(iovw_put_iov(&target, &IOVEC_MAKE_STRING("xxx")));
        ASSERT_OK(iovw_put_iov(&target, &IOVEC_MAKE_STRING("yyy")));
        ASSERT_OK(iovw_put_iov(&target, &IOVEC_MAKE_STRING("zzz")));
        ASSERT_EQ(target.count, 3U);

        ASSERT_OK(iovw_put_iovw(&target, &source));
        ASSERT_EQ(target.count, 6U);
        ASSERT_TRUE(iovec_equal(&target.iovec[0], &IOVEC_MAKE_STRING("xxx")));
        ASSERT_TRUE(iovec_equal(&target.iovec[1], &IOVEC_MAKE_STRING("yyy")));
        ASSERT_TRUE(iovec_equal(&target.iovec[2], &IOVEC_MAKE_STRING("zzz")));
        ASSERT_TRUE(iovec_equal(&target.iovec[3], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&target.iovec[4], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&target.iovec[5], &IOVEC_MAKE_STRING("ccc")));

        /* iovw_put_iovw() does not copy data, hence the pointers must be equal */
        ASSERT_PTR_EQ(target.iovec[3].iov_base, source.iovec[0].iov_base);
        ASSERT_PTR_EQ(target.iovec[4].iov_base, source.iovec[1].iov_base);
        ASSERT_PTR_EQ(target.iovec[5].iov_base, source.iovec[2].iov_base);

        /* Source is unchanged */
        ASSERT_EQ(source.count, 4U);
        ASSERT_TRUE(iovec_equal(&source.iovec[0], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&source.iovec[1], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&source.iovec[2], &IOVEC_MAKE_STRING("ccc")));
        ASSERT_TRUE(iovec_equal(&source.iovec[3], &(struct iovec) {}));

        ASSERT_OK(iovw_put_iovw_full(&target, /* accept_zero= */ true, &source));
        ASSERT_EQ(target.count, 10U);
        ASSERT_TRUE(iovec_equal(&target.iovec[0], &IOVEC_MAKE_STRING("xxx")));
        ASSERT_TRUE(iovec_equal(&target.iovec[1], &IOVEC_MAKE_STRING("yyy")));
        ASSERT_TRUE(iovec_equal(&target.iovec[2], &IOVEC_MAKE_STRING("zzz")));
        ASSERT_TRUE(iovec_equal(&target.iovec[3], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&target.iovec[4], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&target.iovec[5], &IOVEC_MAKE_STRING("ccc")));
        ASSERT_TRUE(iovec_equal(&target.iovec[6], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&target.iovec[7], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&target.iovec[8], &IOVEC_MAKE_STRING("ccc")));
        ASSERT_TRUE(iovec_equal(&target.iovec[9], &(struct iovec) {}));

        /* Cannot pass the same objects */
        ASSERT_ERROR(iovw_put_iovw(&target, &target), EINVAL);
}

TEST(iovw_extend) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_extend(&iovw, NULL, 0));
        ASSERT_OK_ZERO(iovw_extend(&iovw, "foo", 0));
        ASSERT_EQ(iovw.count, 0U);

        /* iovw_extend() copies the data; the wrapper owns the copies. */
        char buf[4] = { 'o', 'n', 'e', '\0' };
        ASSERT_OK(iovw_extend(&iovw, buf, 3));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, 3U);
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "one", 3), 0);

        /* Insert with a NUL */
        ASSERT_OK(iovw_extend(&iovw, buf, 4));
        ASSERT_EQ(iovw.count, 2U);
        ASSERT_EQ(iovw.iovec[1].iov_len, 4U);
        ASSERT_EQ(memcmp(iovw.iovec[1].iov_base, "one\0", 4), 0);

        /* Mutating the caller's buffer does not affect what's stored */
        memset(buf, 'X', sizeof buf);
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "one", 3), 0);

        ASSERT_OK(iovw_extend_full(&iovw, /* accept_zero= */ false, NULL, 0));
        ASSERT_EQ(iovw.count, 2U);
        ASSERT_OK(iovw_extend_full(&iovw, /* accept_zero= */ true, NULL, 0));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &(struct iovec) {}));
}

TEST(iovw_extend_iov) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_extend_iov(&iovw, NULL));
        ASSERT_OK_ZERO(iovw_extend_iov(&iovw, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 0U);

        ASSERT_OK(iovw_extend_iov(&iovw, &IOVEC_MAKE_STRING("aaa")));
        ASSERT_OK(iovw_extend_iov(&iovw, &IOVEC_MAKE_STRING("bbb")));
        ASSERT_OK(iovw_extend_iov(&iovw, &IOVEC_MAKE_STRING("ccc")));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[0], &IOVEC_MAKE_STRING("aaa")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &IOVEC_MAKE_STRING("bbb")));
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &IOVEC_MAKE_STRING("ccc")));

        ASSERT_OK(iovw_extend_iov_full(&iovw, /* accept_zero= */ false, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_OK(iovw_extend_iov_full(&iovw, /* accept_zero= */ true, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 4U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[3], &(struct iovec) {}));
}

TEST(iovw_extend_iovw) {
        _cleanup_(iovw_done_free) struct iovec_wrapper target = {};
        _cleanup_(iovw_done) struct iovec_wrapper source = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_extend_iovw(&target, NULL));
        ASSERT_OK_ZERO(iovw_extend_iovw(&target, &source));
        ASSERT_EQ(target.count, 0U);

        ASSERT_OK(iovw_put(&source, (char*) "one", 3));
        ASSERT_OK(iovw_put(&source, (char*) "twotwo", 6));
        ASSERT_OK(iovw_put_full(&source, /* accept_zero= */ true, NULL, 0));
        ASSERT_EQ(source.count, 3U);

        /* Pre-seed target with one entry to check that append adds on top rather than replacing */
        char *seed = strdup("zero");
        ASSERT_NOT_NULL(seed);
        ASSERT_OK(iovw_put(&target, seed, strlen(seed)));

        ASSERT_OK(iovw_extend_iovw(&target, &source));
        ASSERT_EQ(target.count, 3U);

        /* Appended entries must be fresh copies, not aliases of the source entries */
        ASSERT_TRUE(target.iovec[1].iov_base != source.iovec[0].iov_base);
        ASSERT_TRUE(target.iovec[2].iov_base != source.iovec[1].iov_base);

        ASSERT_EQ(target.iovec[1].iov_len, 3U);
        ASSERT_EQ(memcmp(target.iovec[1].iov_base, "one", 3), 0);
        ASSERT_EQ(target.iovec[2].iov_len, 6U);
        ASSERT_EQ(memcmp(target.iovec[2].iov_base, "twotwo", 6), 0);

        ASSERT_OK(iovw_extend_iovw_full(&target, /* accept_zero= */ true, &source));
        ASSERT_EQ(target.count, 6U);
        ASSERT_TRUE(iovec_equal(&target.iovec[0], &IOVEC_MAKE_STRING("zero")));
        ASSERT_TRUE(iovec_equal(&target.iovec[1], &IOVEC_MAKE_STRING("one")));
        ASSERT_TRUE(iovec_equal(&target.iovec[2], &IOVEC_MAKE_STRING("twotwo")));
        ASSERT_TRUE(iovec_equal(&target.iovec[3], &IOVEC_MAKE_STRING("one")));
        ASSERT_TRUE(iovec_equal(&target.iovec[4], &IOVEC_MAKE_STRING("twotwo")));
        ASSERT_TRUE(iovec_equal(&target.iovec[5], &(struct iovec) {}));

        /* Source is unchanged */
        ASSERT_EQ(source.count, 3U);

        /* Cannot pass the same objects */
        ASSERT_ERROR(iovw_extend_iovw(&target, &target), EINVAL);
}

TEST(iovw_consume) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        char *p = strdup("consumed");
        ASSERT_NOT_NULL(p);
        ASSERT_OK(iovw_consume(&iovw, p, strlen(p)));
        ASSERT_EQ(iovw.count, 1U);
        /* iovw_consume moves ownership in place, no copy */
        ASSERT_PTR_EQ(iovw.iovec[0].iov_base, p);

        /* Zero-length: iovw_put returns 0 without adding anything. Even in that case, iovw_consume() frees
         * the payload. Confirm by strdup'ing something to verify that when running with sanitizer/valgrind. */
        char *q = ASSERT_NOT_NULL(strdup(""));
        ASSERT_OK_ZERO(iovw_consume(&iovw, q, 0));
        ASSERT_EQ(iovw.count, 1U);

        ASSERT_OK(iovw_consume_full(&iovw, /* accept_zero= */ false, NULL, 0));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_OK(iovw_consume_full(&iovw, /* accept_zero= */ true, NULL, 0));
        ASSERT_EQ(iovw.count, 2U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &(struct iovec) {}));
        q = ASSERT_NOT_NULL(strdup(""));
        ASSERT_OK(iovw_consume_full(&iovw, /* accept_zero= */ true, q, 0));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &(struct iovec) {}));
}

TEST(iovw_consume_iov) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        ASSERT_OK_ZERO(iovw_consume_iov(&iovw, NULL));
        ASSERT_EQ(iovw.count, 0U);

        ASSERT_OK_ZERO(iovw_consume_iov(&iovw, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 0U);

        struct iovec iov = {
                .iov_base = ASSERT_NOT_NULL(strdup("consumed")),
                .iov_len = strlen("consumed"),
        };
        ASSERT_OK(iovw_consume_iov(&iovw, &iov));
        ASSERT_EQ(iovw.count, 1U);
        /* iovw_consume_iov takes the ownership of the buffer, and emptifies the iovec. */
        ASSERT_NULL(iov.iov_base);
        ASSERT_EQ(iov.iov_len, 0U);

        iov = (struct iovec) {
                .iov_base = ASSERT_NOT_NULL(strdup("")),
                .iov_len = 0,
        };
        ASSERT_OK_ZERO(iovw_consume_iov(&iovw, &iov));
        ASSERT_EQ(iovw.count, 1U);
        /* zero length iovec is also freed */
        ASSERT_NULL(iov.iov_base);
        ASSERT_EQ(iov.iov_len, 0U);

        ASSERT_OK(iovw_consume_iov_full(&iovw, /* accept_zero= */ false, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_OK(iovw_consume_iov_full(&iovw, /* accept_zero= */ true, &(struct iovec) {}));
        ASSERT_EQ(iovw.count, 2U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[1], &(struct iovec) {}));
        iov = (struct iovec) {
                .iov_base = ASSERT_NOT_NULL(strdup("")),
                .iov_len = 0,
        };
        ASSERT_OK(iovw_consume_iov_full(&iovw, /* accept_zero= */ true, &iov));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_TRUE(iovec_equal(&iovw.iovec[2], &(struct iovec) {}));
}

TEST(iovw_isempty) {
        ASSERT_TRUE(iovw_isempty(NULL));

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_TRUE(iovw_isempty(&iovw));

        ASSERT_OK(iovw_put(&iovw, (char*) "x", 1));
        ASSERT_FALSE(iovw_isempty(&iovw));
}

TEST(iovw_put_string_field) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        ASSERT_OK(iovw_put_string_field(&iovw, "FOO=", "bar"));
        ASSERT_OK(iovw_put_string_field(&iovw, "BAZ=", "quux"));
        ASSERT_EQ(iovw.count, 2U);

        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("FOO=bar"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "FOO=bar", strlen("FOO=bar")), 0);
        ASSERT_EQ(iovw.iovec[1].iov_len, strlen("BAZ=quux"));
        ASSERT_EQ(memcmp(iovw.iovec[1].iov_base, "BAZ=quux", strlen("BAZ=quux")), 0);

        /* Non-replacing put: a second FOO= just appends rather than replacing */
        ASSERT_OK(iovw_put_string_field(&iovw, "FOO=", "second"));
        ASSERT_EQ(iovw.count, 3U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("FOO=bar"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "FOO=bar", strlen("FOO=bar")), 0);
        ASSERT_EQ(iovw.iovec[2].iov_len, strlen("FOO=second"));
        ASSERT_EQ(memcmp(iovw.iovec[2].iov_base, "FOO=second", strlen("FOO=second")), 0);
}

TEST(iovw_replace_string_field) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        /* If the field does not exist yet, replace acts like put */
        ASSERT_OK(iovw_replace_string_field(&iovw, "A=", "1"));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("A=1"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "A=1", strlen("A=1")), 0);

        /* Replacing an existing field updates it in place */
        ASSERT_OK(iovw_replace_string_field(&iovw, "A=", "twentytwo"));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("A=twentytwo"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "A=twentytwo", strlen("A=twentytwo")), 0);

        /* Distinct field still appends */
        ASSERT_OK(iovw_replace_string_field(&iovw, "B=", "x"));
        ASSERT_EQ(iovw.count, 2U);
}

TEST(iovw_put_string_fieldf) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        ASSERT_OK(iovw_put_string_fieldf(&iovw, "N=", "%d-%s", 42, "answer"));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("N=42-answer"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "N=42-answer", strlen("N=42-answer")), 0);

        /* Replacing variant */
        ASSERT_OK(iovw_replace_string_fieldf(&iovw, "N=", "%d", 7));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("N=7"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "N=7", strlen("N=7")), 0);
}

TEST(iovw_put_string_field_free) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        /* iovw_put_string_field_free takes ownership of the value string (frees it on return). */
        char *v = strdup("hello");
        ASSERT_NOT_NULL(v);
        ASSERT_OK(iovw_put_string_field_free(&iovw, "K=", v));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, strlen("K=hello"));
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "K=hello", strlen("K=hello")), 0);
}

TEST(iovw_rebase) {
        /* iovw_rebase shifts all iov_base pointers from an old base to a new base. Fabricate a
         * stand-in "old base" and "new base" and a wrapper with offsets pointing into the old
         * base, then verify they get rewritten to point into the new base. */

        uint8_t old_base[64] = {}, new_base[64] = {};
        for (size_t i = 0; i < sizeof old_base; i++) {
                old_base[i] = (uint8_t) i;
                new_base[i] = (uint8_t) (100 + i);
        }

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};

        ASSERT_OK(iovw_put(&iovw, old_base + 0, 4));
        ASSERT_OK(iovw_put(&iovw, old_base + 10, 2));
        ASSERT_OK(iovw_put(&iovw, old_base + 30, 8));
        ASSERT_EQ(iovw.count, 3U);

        iovw_rebase(&iovw, old_base, new_base);

        ASSERT_PTR_EQ(iovw.iovec[0].iov_base, new_base + 0);
        ASSERT_PTR_EQ(iovw.iovec[1].iov_base, new_base + 10);
        ASSERT_PTR_EQ(iovw.iovec[2].iov_base, new_base + 30);

        /* Lengths are preserved */
        ASSERT_EQ(iovw.iovec[0].iov_len, 4U);
        ASSERT_EQ(iovw.iovec[1].iov_len, 2U);
        ASSERT_EQ(iovw.iovec[2].iov_len, 8U);

        /* And the contents through the new base match what we staged there */
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, new_base + 0, 4), 0);
        ASSERT_EQ(memcmp(iovw.iovec[1].iov_base, new_base + 10, 2), 0);
        ASSERT_EQ(memcmp(iovw.iovec[2].iov_base, new_base + 30, 8), 0);
}

TEST(iovw_size) {
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_EQ(iovw_size(&iovw), 0U);

        ASSERT_OK(iovw_put(&iovw, (char*) "abcd", 4));
        ASSERT_OK(iovw_put(&iovw, (char*) "efghij", 6));
        ASSERT_OK(iovw_put(&iovw, (char*) "kl", 2));
        ASSERT_EQ(iovw_size(&iovw), 12U);

        ASSERT_EQ(iovw_size(NULL), 0U);
}

TEST(iovw_concat) {
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};

        /* Empty wrapper -> empty string with 0 length */
        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(iovw_concat(&iovw, &iov));
        ASSERT_FALSE(iovec_is_set(&iov));
        ASSERT_STREQ(iov.iov_base, "");
        iovec_done(&iov);

        ASSERT_OK(iovw_put(&iovw, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&iovw, (char*) "\0", 1));
        ASSERT_OK(iovw_put(&iovw, (char*) "bar", 4));

        ASSERT_OK(iovw_concat(&iovw, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE("foo\0bar\0", 8)));
}

TEST(iovw_to_cstring) {
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        _cleanup_free_ char *s;

        /* Empty wrapper → empty string */
        s = iovw_to_cstring(&iovw);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "");
        s = mfree(s);

        ASSERT_OK(iovw_put(&iovw, (char*) "foo", 3));
        ASSERT_OK(iovw_put(&iovw, (char*) "/", 1));
        ASSERT_OK(iovw_put(&iovw, (char*) "bar", 3));

        s = iovw_to_cstring(&iovw);
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s, "foo/bar");
}

TEST(iovw_merge_and_iovec_split) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {}, iovw2 = {};
        _cleanup_(iovec_done) struct iovec v = {}, v2 = {};
        uint8_t *p;

        struct iovec
                a = IOVEC_MAKE_STRING("aaa"),
                b = IOVEC_MAKE_STRING("bbbb"),
                c = IOVEC_MAKE_STRING("ccccc");

        /* single entry */
        ASSERT_OK(iovw_extend_iov(&iovw, &a));

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint8_t), &v));
        ASSERT_EQ(v.iov_len, 1 + a.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_OK(iovec_split(&v, sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint16_t), &v));
        ASSERT_EQ(v.iov_len, sizeof(uint16_t) + a.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_OK(iovec_split(&v, sizeof(uint16_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint32_t), &v));
        ASSERT_EQ(v.iov_len, sizeof(uint32_t) + a.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_OK(iovec_split(&v, sizeof(uint32_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        /* multiple entries */
        ASSERT_OK(iovw_extend_iov(&iovw, &b));
        ASSERT_OK(iovw_extend_iov(&iovw, &c));

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint8_t), &v));
        ASSERT_EQ(v.iov_len, 3 + a.iov_len + b.iov_len + c.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_EQ(*p++, b.iov_len);
        ASSERT_EQ(memcmp(p, b.iov_base, b.iov_len), 0);
        p += b.iov_len;
        ASSERT_EQ(*p++, c.iov_len);
        ASSERT_EQ(memcmp(p, c.iov_base, c.iov_len), 0);
        ASSERT_OK(iovec_split(&v, sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint16_t), &v));
        ASSERT_EQ(v.iov_len, 3 * sizeof(uint16_t) + a.iov_len + b.iov_len + c.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, b.iov_len);
        ASSERT_EQ(memcmp(p, b.iov_base, b.iov_len), 0);
        p += b.iov_len;
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, c.iov_len);
        ASSERT_EQ(memcmp(p, c.iov_base, c.iov_len), 0);
        ASSERT_OK(iovec_split(&v, sizeof(uint16_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        ASSERT_OK(iovw_merge(&iovw, sizeof(uint32_t), &v));
        ASSERT_EQ(v.iov_len, 3 * sizeof(uint32_t) + a.iov_len + b.iov_len + c.iov_len);
        p = ASSERT_NOT_NULL(v.iov_base);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, a.iov_len);
        ASSERT_EQ(memcmp(p, a.iov_base, a.iov_len), 0);
        p += a.iov_len;
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, b.iov_len);
        ASSERT_EQ(memcmp(p, b.iov_base, b.iov_len), 0);
        p += b.iov_len;
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, 0);
        ASSERT_EQ(*p++, c.iov_len);
        ASSERT_EQ(memcmp(p, c.iov_base, c.iov_len), 0);
        ASSERT_OK(iovec_split(&v, sizeof(uint32_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        /* with empty entries */
        _cleanup_(iovw_done) struct iovec_wrapper with_empty = {
                .iovec = ASSERT_PTR(new0(struct iovec, 6)),
                .count = 6,
        };
        with_empty.iovec[0] = a;
        with_empty.iovec[2] = b;
        with_empty.iovec[4] = c;
        ASSERT_OK(iovw_merge(&iovw, sizeof(uint8_t), &v));
        ASSERT_OK(iovw_merge(&with_empty, sizeof(uint8_t), &v2));
        ASSERT_TRUE(iovec_equal(&v, &v2));

        iovec_done(&v);
        iovec_done(&v2);

        size_t sz = 6 + a.iov_len + b.iov_len + c.iov_len;
        _cleanup_free_ uint8_t *buf = ASSERT_PTR(new(uint8_t, sz));
        p = buf;
        *p++ = a.iov_len;
        p = mempcpy(p, a.iov_base, a.iov_len);
        *p++ = 0;
        *p++ = b.iov_len;
        p = mempcpy(p, b.iov_base, b.iov_len);
        *p++ = 0;
        *p++ = c.iov_len;
        p = mempcpy(p, c.iov_base, c.iov_len);
        *p++ = 0;
        ASSERT_OK(iovec_split(&IOVEC_MAKE(buf, sz), sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));

        iovw_done_free(&iovw2);

        /* truncated */
        ASSERT_OK(iovw_merge(&iovw, sizeof(uint8_t), &v));
        ASSERT_ERROR(iovec_split(&IOVEC_MAKE(v.iov_base, v.iov_len - 1), sizeof(uint8_t), &iovw2), EBADMSG);

        iovec_done(&v);

        /* too long */
        _cleanup_(iovec_done) struct iovec large = {};
        ASSERT_OK(random_bytes_allocate_iovec(256, &large));
        ASSERT_ERROR(iovw_merge(&(struct iovec_wrapper) { .iovec = &large, .count = 1, }, sizeof(uint8_t), &v), ERANGE);
        ASSERT_OK(iovw_merge(&(struct iovec_wrapper) { .iovec = &large, .count = 1, }, sizeof(uint16_t), &v));
        ASSERT_OK(iovec_split(&v, sizeof(uint16_t), &iovw2));
        ASSERT_EQ(iovw2.count, 1u);
        ASSERT_TRUE(iovec_equal(&iovw2.iovec[0], &large));

        iovec_done(&v);
        iovw_done_free(&iovw2);

        /* No entry */
        ASSERT_OK(iovw_merge(&(struct iovec_wrapper) {}, sizeof(uint8_t), &v));
        ASSERT_FALSE(iovec_is_set(&v));

        ASSERT_OK(iovw_merge(NULL, sizeof(uint8_t), &v));
        ASSERT_FALSE(iovec_is_set(&v));

        ASSERT_OK(iovec_split(&(struct iovec) {}, sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_isempty(&iovw2));

        ASSERT_OK(iovec_split(NULL, sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_isempty(&iovw2));

        /* empty entry only */
        ASSERT_OK(iovw_merge(&(struct iovec_wrapper) { .iovec = &(struct iovec) {}, .count = 1, }, sizeof(uint8_t), &v));
        ASSERT_FALSE(iovec_is_set(&v));

        ASSERT_OK(iovec_split(&IOVEC_MAKE("", 1), sizeof(uint8_t), &iovw2));
        ASSERT_TRUE(iovw_isempty(&iovw2));

}

DEFINE_TEST_MAIN(LOG_INFO);
