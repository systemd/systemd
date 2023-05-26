/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memstream-util.h"
#include "string-util.h"
#include "tests.h"

TEST(memstream_done) {
        _cleanup_(memstream_done) MemStream m = {};

        assert_se(memstream_open(&m, NULL) >= 0);
}

TEST(memstream_empty) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        assert_se(memstream_open(&m, NULL) >= 0);
        assert_se(memstream_close(&m, &buf, &sz) >= 0);
        assert_se(streq(buf, ""));
        assert_se(sz == 0);
}

TEST(memstream) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        FILE *f;

        assert_se(memstream_open(&m, &f) >= 0);
        fputs("hoge", f);
        fputs("おはよう！", f);
        fputs(u8"😀😀😀", f);
        assert_se(memstream_close(&m, &buf, &sz) >= 0);
        assert_se(streq(buf, u8"hogeおはよう！😀😀😀"));
        assert_se(sz == strlen(u8"hogeおはよう！😀😀😀"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
