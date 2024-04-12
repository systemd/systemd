/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memstream-util.h"
#include "string-util.h"
#include "tests.h"

TEST(memstream_done) {
        _cleanup_(memstream_done) MemStream m = {};

        assert_se(memstream_init(&m));
}

TEST(memstream_empty) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        assert_se(memstream_init(&m));
        assert_se(memstream_finalize(&m, &buf, &sz) >= 0);
        ASSERT_STREQ(buf, "");
        assert_se(sz == 0);
}

TEST(memstream) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        FILE *f;

        assert_se(f = memstream_init(&m));
        fputs("hoge", f);
        fputs("おはよう！", f);
        fputs(u8"😀😀😀", f);
        assert_se(memstream_finalize(&m, &buf, &sz) >= 0);
        ASSERT_STREQ(buf, u8"hogeおはよう！😀😀😀");
        assert_se(sz == strlen(u8"hogeおはよう！😀😀😀"));

        buf = mfree(buf);

        assert_se(f = memstream_init(&m));
        fputs("second", f);
        assert_se(memstream_finalize(&m, &buf, &sz) >= 0);
        ASSERT_STREQ(buf, "second");
        assert_se(sz == strlen("second"));
}

TEST(memstream_dump) {
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        assert_se(f = memstream_init(&m));
        fputs("first", f);
        assert_se(memstream_dump(LOG_DEBUG, &m) >= 0);

        assert_se(f = memstream_init(&m));
        fputs("second", f);
        assert_se(memstream_dump(LOG_DEBUG, &m) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
