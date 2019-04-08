/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

#include "string-util.h"
#include "strxcpyx.h"
#include "util.h"

static void test_strpcpy(void) {
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

static void test_strpcpyf(void) {
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

static void test_strpcpyl(void) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpyl(&s, space_left, "waldo", " test", " waldo. ", NULL);
        space_left = strpcpyl(&s, space_left, "Banana", NULL);

        assert_se(streq(target, "waldo test waldo. Banana"));
        assert_se(space_left == 1);
}

static void test_strscpy(void) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpy(target, space_left, "12345");

        assert_se(streq(target, "12345"));
        assert_se(space_left == 20);
}

static void test_strscpyl(void) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpyl(target, space_left, "12345", "waldo", "waldo", NULL);

        assert_se(streq(target, "12345waldowaldo"));
        assert_se(space_left == 10);
}

int main(int argc, char *argv[]) {
        test_strpcpy();
        test_strpcpyf();
        test_strpcpyl();
        test_strscpy();
        test_strscpyl();

        return 0;
}
