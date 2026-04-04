/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memstream-util.h"
#include "tests.h"

TEST(memstream_done) {
        _cleanup_done(memstream) MemStream m = {};

        ASSERT_NOT_NULL(memstream_init(&m));
}

TEST(memstream_empty) {
        _cleanup_done(memstream) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        ASSERT_NOT_NULL(memstream_init(&m));
        ASSERT_OK(memstream_finalize(&m, &buf, &sz));
        ASSERT_STREQ(buf, "");
        ASSERT_EQ(sz, 0u);
}

TEST(memstream) {
        _cleanup_done(memstream) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        FILE *f;

        ASSERT_NOT_NULL(f = memstream_init(&m));
        fputs("hoge", f);
        fputs("おはよう！", f);
        fputs(UTF8("😀😀😀"), f);
        ASSERT_OK(memstream_finalize(&m, &buf, &sz));
        ASSERT_STREQ(buf, UTF8("hogeおはよう！😀😀😀"));
        ASSERT_EQ(sz, strlen(UTF8("hogeおはよう！😀😀😀")));

        buf = mfree(buf);

        ASSERT_NOT_NULL(f = memstream_init(&m));
        fputs("second", f);
        ASSERT_OK(memstream_finalize(&m, &buf, &sz));
        ASSERT_STREQ(buf, "second");
        ASSERT_EQ(sz, strlen("second"));
}

TEST(memstream_dump) {
        _cleanup_done(memstream) MemStream m = {};
        FILE *f;

        ASSERT_NOT_NULL(f = memstream_init(&m));
        fputs("first", f);
        ASSERT_OK(memstream_dump(LOG_DEBUG, &m));

        ASSERT_NOT_NULL(f = memstream_init(&m));
        fputs("second", f);
        ASSERT_OK(memstream_dump(LOG_DEBUG, &m));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
