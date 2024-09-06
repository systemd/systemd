/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "string-util.h"
#include "strxcpyx.h"
#include "tests.h"

TEST(strpcpy) {
        char target[25];
        char *s = target;
        size_t space_left;
        bool truncated;

        space_left = sizeof(target);
        space_left = strpcpy_full(&s, space_left, "12345", &truncated);
        assert_se(!truncated);
        space_left = strpcpy_full(&s, space_left, "hey hey hey", &truncated);
        assert_se(!truncated);
        space_left = strpcpy_full(&s, space_left, "waldo", &truncated);
        assert_se(!truncated);
        space_left = strpcpy_full(&s, space_left, "ba", &truncated);
        assert_se(!truncated);
        space_left = strpcpy_full(&s, space_left, "r", &truncated);
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "12345hey hey heywaldobar");

        space_left = strpcpy_full(&s, space_left, "", &truncated);
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "12345hey hey heywaldobar");

        space_left = strpcpy_full(&s, space_left, "f", &truncated);
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "12345hey hey heywaldobar");

        space_left = strpcpy_full(&s, space_left, "", &truncated);
        assert_se(!truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "12345hey hey heywaldobar");

        space_left = strpcpy_full(&s, space_left, "foo", &truncated);
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "12345hey hey heywaldobar");
}

TEST(strpcpyf) {
        char target[25];
        char *s = target;
        size_t space_left;
        bool truncated;

        space_left = sizeof(target);
        space_left = strpcpyf_full(&s, space_left, &truncated, "space left: %zu. ", space_left);
        assert_se(!truncated);
        space_left = strpcpyf_full(&s, space_left, &truncated, "foo%s", "bar");
        assert_se(!truncated);
        assert_se(space_left == 3);
        ASSERT_STREQ(target, "space left: 25. foobar");

        space_left = strpcpyf_full(&s, space_left, &truncated, "%i", 42);
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "space left: 25. foobar42");

        space_left = strpcpyf_full(&s, space_left, &truncated, "%s", "");
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "space left: 25. foobar42");

        space_left = strpcpyf_full(&s, space_left, &truncated, "%c", 'x');
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "space left: 25. foobar42");

        space_left = strpcpyf_full(&s, space_left, &truncated, "%s", "");
        assert_se(!truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "space left: 25. foobar42");

        space_left = strpcpyf_full(&s, space_left, &truncated, "abc%s", "hoge");
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "space left: 25. foobar42");

        /* test overflow */
        s = target;
        space_left = strpcpyf_full(&s, 12, &truncated, "00 left: %i. ", 999);
        assert_se(truncated);
        ASSERT_STREQ(target, "00 left: 99");
        assert_se(space_left == 0);
        assert_se(target[12] == '2');
}

TEST(strpcpyl) {
        char target[25];
        char *s = target;
        size_t space_left;
        bool truncated;

        space_left = sizeof(target);
        space_left = strpcpyl_full(&s, space_left, &truncated, "waldo", " test", " waldo. ", NULL);
        assert_se(!truncated);
        space_left = strpcpyl_full(&s, space_left, &truncated, "Banana", NULL);
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "waldo test waldo. Banana");

        space_left = strpcpyl_full(&s, space_left, &truncated, "", "", "", NULL);
        assert_se(!truncated);
        assert_se(space_left == 1);
        ASSERT_STREQ(target, "waldo test waldo. Banana");

        space_left = strpcpyl_full(&s, space_left, &truncated, "", "x", "", NULL);
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "waldo test waldo. Banana");

        space_left = strpcpyl_full(&s, space_left, &truncated, "hoge", NULL);
        assert_se(truncated);
        assert_se(space_left == 0);
        ASSERT_STREQ(target, "waldo test waldo. Banana");
}

TEST(strscpy) {
        char target[25];
        size_t space_left;
        bool truncated;

        space_left = sizeof(target);
        space_left = strscpy_full(target, space_left, "12345", &truncated);
        assert_se(!truncated);

        ASSERT_STREQ(target, "12345");
        assert_se(space_left == 20);
}

TEST(strscpyl) {
        char target[25];
        size_t space_left;
        bool truncated;

        space_left = sizeof(target);
        space_left = strscpyl_full(target, space_left, &truncated, "12345", "waldo", "waldo", NULL);
        assert_se(!truncated);

        ASSERT_STREQ(target, "12345waldowaldo");
        assert_se(space_left == 10);
}

TEST(sd_event_code_migration) {
        char b[100 * DECIMAL_STR_MAX(unsigned) + 1];
        char c[100 * DECIMAL_STR_MAX(unsigned) + 1], *p;
        unsigned i;
        size_t l;
        int o, r;

        for (i = o = 0; i < 100; i++) {
                r = snprintf(&b[o], sizeof(b) - o, "%u ", i);
                assert_se(r >= 0 && r < (int) sizeof(b) - o);
                o += r;
        }

        p = c;
        l = sizeof(c);
        for (i = 0; i < 100; i++)
                l = strpcpyf(&p, l, "%u ", i);

        ASSERT_STREQ(b, c);
}

DEFINE_TEST_MAIN(LOG_INFO);
