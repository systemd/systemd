/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "string-util.h"
#include "strxcpyx.h"
#include "tests.h"
#include "util.h"

TEST(strpcpy) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpy(&s, space_left, "12345");
        space_left = strpcpy(&s, space_left, "hey hey hey");
        space_left = strpcpy(&s, space_left, "waldo");
        space_left = strpcpy(&s, space_left, "ba");
        space_left = strpcpy(&s, space_left, "r");
        space_left = strpcpy(&s, space_left, "foo");

        assert_se(streq(target, "12345hey hey heywaldobar"));
        assert_se(space_left == 0);
}

TEST(strpcpyf) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpyf(&s, space_left, "space left: %zu. ", space_left);
        space_left = strpcpyf(&s, space_left, "foo%s", "bar");

        assert_se(streq(target, "space left: 25. foobar"));
        assert_se(space_left == 3);

        /* test overflow */
        s = target;
        space_left = strpcpyf(&s, 12, "00 left: %i. ", 999);
        assert_se(streq(target, "00 left: 99"));
        assert_se(space_left == 0);
        assert_se(target[12] == '2');
}

TEST(strpcpyl) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpyl(&s, space_left, "waldo", " test", " waldo. ", NULL);
        space_left = strpcpyl(&s, space_left, "Banana", NULL);

        assert_se(streq(target, "waldo test waldo. Banana"));
        assert_se(space_left == 1);
}

TEST(strscpy) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpy(target, space_left, "12345");

        assert_se(streq(target, "12345"));
        assert_se(space_left == 20);
}

TEST(strscpyl) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpyl(target, space_left, "12345", "waldo", "waldo", NULL);

        assert_se(streq(target, "12345waldowaldo"));
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

        assert_se(streq(b, c));
}

DEFINE_TEST_MAIN(LOG_INFO);
