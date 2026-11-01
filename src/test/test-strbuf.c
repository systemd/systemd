/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nulstr-util.h"
#include "strbuf.h"
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
        l = ASSERT_NOT_NULL(strv_parse_nulstr(sb->buf, sb->len));

        ASSERT_STREQ(l[0], ""); /* root */
        ASSERT_STREQ(l[1], "waldo");
        ASSERT_STREQ(l[2], "foo");
        ASSERT_STREQ(l[3], "bar");
        ASSERT_STREQ(l[4], "waldorf");
        ASSERT_NULL(l[5]);

        ASSERT_EQ(sb->nodes_count, 5U); /* root + 4 non-duplicates */
        ASSERT_EQ(sb->dedup_count, 4U);
        ASSERT_EQ(sb->in_count, 8U);

        ASSERT_EQ(sb->in_len, 29U);    /* length of all strings added */
        ASSERT_EQ(sb->dedup_len, 11U); /* length of all strings duplicated */
        ASSERT_EQ(sb->len, 23U);       /* buffer length: in - dedup + \0 for each node */

        /* check the returned offsets and the respective content in the buffer */
        ASSERT_EQ(a, 1);
        ASSERT_EQ(b, 7);
        ASSERT_EQ(c, 11);
        ASSERT_EQ(d, 1);
        ASSERT_EQ(e, 2);
        ASSERT_EQ(f, 4);
        ASSERT_EQ(g, 15);
        ASSERT_EQ(h, 0);

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
