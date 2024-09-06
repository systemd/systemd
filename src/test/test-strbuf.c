/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "nulstr-util.h"
#include "strbuf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(strbuf) {
        _cleanup_(strbuf_freep) struct strbuf *sb = NULL;
        _cleanup_strv_free_ char **l = NULL;
        ssize_t a, b, c, d, e, f, g, h;

        sb = strbuf_new();

        a = strbuf_add_string(sb, "waldo");
        b = strbuf_add_string(sb, "foo");
        c = strbuf_add_string(sb, "bar");
        d = strbuf_add_string(sb, "waldo");   /* duplicate */
        e = strbuf_add_string(sb, "aldo");    /* duplicate */
        f = strbuf_add_string(sb, "do");      /* duplicate */
        g = strbuf_add_string(sb, "waldorf"); /* not a duplicate: matches from tail */
        h = strbuf_add_string(sb, "");

        /* check the content of the buffer directly */
        l = strv_parse_nulstr(sb->buf, sb->len);
        assert_se(l);

        ASSERT_STREQ(l[0], ""); /* root */
        ASSERT_STREQ(l[1], "waldo");
        ASSERT_STREQ(l[2], "foo");
        ASSERT_STREQ(l[3], "bar");
        ASSERT_STREQ(l[4], "waldorf");
        ASSERT_NULL(l[5]);

        assert_se(sb->nodes_count == 5); /* root + 4 non-duplicates */
        assert_se(sb->dedup_count == 4);
        assert_se(sb->in_count == 8);

        assert_se(sb->in_len == 29);    /* length of all strings added */
        assert_se(sb->dedup_len == 11); /* length of all strings duplicated */
        assert_se(sb->len == 23);       /* buffer length: in - dedup + \0 for each node */

        /* check the returned offsets and the respective content in the buffer */
        assert_se(a == 1);
        assert_se(b == 7);
        assert_se(c == 11);
        assert_se(d == 1);
        assert_se(e == 2);
        assert_se(f == 4);
        assert_se(g == 15);
        assert_se(h == 0);

        ASSERT_STREQ(sb->buf + a, "waldo");
        ASSERT_STREQ(sb->buf + b, "foo");
        ASSERT_STREQ(sb->buf + c, "bar");
        ASSERT_STREQ(sb->buf + d, "waldo");
        ASSERT_STREQ(sb->buf + e, "aldo");
        ASSERT_STREQ(sb->buf + f, "do");
        ASSERT_STREQ(sb->buf + g, "waldorf");
        ASSERT_STREQ(sb->buf + h, "");

        strbuf_complete(sb);
        ASSERT_NULL(sb->root);
}

DEFINE_TEST_MAIN(LOG_INFO);
