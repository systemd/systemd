/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/uio.h>

#include "alloc-util.h"
#include "iovec-wrapper.h"
#include "tests.h"

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
}

TEST(iovw_append) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        /* iovw_append copies the data; the wrapper owns the copies. */
        char buf[4] = { 'o', 'n', 'e', '\0' };
        ASSERT_OK(iovw_append(&iovw, buf, 3));
        ASSERT_EQ(iovw.count, 1U);
        ASSERT_EQ(iovw.iovec[0].iov_len, 3U);
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "one", 3), 0);

        /* Insert with a NUL */
        ASSERT_OK_ZERO(iovw_append(&iovw, buf, 4));
        ASSERT_EQ(iovw.count, 2U);
        ASSERT_EQ(iovw.iovec[1].iov_len, 4U);
        ASSERT_EQ(memcmp(iovw.iovec[1].iov_base, "one\0", 4), 0);

        /* Mutating the caller's buffer does not affect what's stored */
        memset(buf, 'X', sizeof buf);
        ASSERT_EQ(memcmp(iovw.iovec[0].iov_base, "one", 3), 0);
}

TEST(iovw_consume) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};

        char *p = strdup("consumed");
        ASSERT_NOT_NULL(p);
        ASSERT_OK(iovw_consume(&iovw, p, strlen(p)));
        ASSERT_EQ(iovw.count, 1U);
        /* iovw_consume moves ownership in place, no copy */
        ASSERT_PTR_EQ(iovw.iovec[0].iov_base, p);

        /* Zero-length: iovw_put returns 0 without adding anything, and does not free the payload.
         * Confirm by strdup'ing something and explicitly freeing it afterwards. */
        _cleanup_free_ char *q = strdup("");
        ASSERT_NOT_NULL(q);
        ASSERT_OK_ZERO(iovw_consume(&iovw, q, 0));
        ASSERT_EQ(iovw.count, 1U);
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
}

TEST(iovw_append_iovw) {
        _cleanup_(iovw_done_free) struct iovec_wrapper target = {};
        _cleanup_(iovw_done) struct iovec_wrapper source = {};

        /* Appending an empty/NULL source is a no-op */
        ASSERT_OK_ZERO(iovw_append_iovw(&target, NULL));
        ASSERT_OK_ZERO(iovw_append_iovw(&target, &source));
        ASSERT_EQ(target.count, 0U);

        ASSERT_OK(iovw_put(&source, (char*) "one", 3));
        ASSERT_OK(iovw_put(&source, (char*) "twotwo", 6));
        ASSERT_EQ(source.count, 2U);

        /* Pre-seed target with one entry to check that append adds on top rather than replacing */
        char *seed = strdup("zero");
        ASSERT_NOT_NULL(seed);
        ASSERT_OK(iovw_put(&target, seed, strlen(seed)));

        ASSERT_OK(iovw_append_iovw(&target, &source));
        ASSERT_EQ(target.count, 3U);

        /* Appended entries must be fresh copies, not aliases of the source entries */
        ASSERT_TRUE(target.iovec[1].iov_base != source.iovec[0].iov_base);
        ASSERT_TRUE(target.iovec[2].iov_base != source.iovec[1].iov_base);

        ASSERT_EQ(target.iovec[1].iov_len, 3U);
        ASSERT_EQ(memcmp(target.iovec[1].iov_base, "one", 3), 0);
        ASSERT_EQ(target.iovec[2].iov_len, 6U);
        ASSERT_EQ(memcmp(target.iovec[2].iov_base, "twotwo", 6), 0);

        /* Source is unchanged */
        ASSERT_EQ(source.count, 2U);
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

DEFINE_TEST_MAIN(LOG_INFO);
