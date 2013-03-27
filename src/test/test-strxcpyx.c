/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Thomas H.P. Andersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "util.h"
#include "strv.h"
#include "strxcpyx.h"

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

        assert(streq(target, "12345hey hey heywaldobar"));
        assert(space_left == 0);
}

static void test_strpcpyf(void) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpyf(&s, space_left, "space left: %zd. ", space_left);
        space_left = strpcpyf(&s, space_left, "foo%s", "bar");

        assert(streq(target, "space left: 25. foobar"));
        assert(space_left == 3);
}

static void test_strpcpyl(void) {
        char target[25];
        char *s = target;
        size_t space_left;

        space_left = sizeof(target);
        space_left = strpcpyl(&s, space_left, "waldo", " test", " waldo. ", NULL);
        space_left = strpcpyl(&s, space_left, "Banana", NULL);

        assert(streq(target, "waldo test waldo. Banana"));
        assert(space_left == 1);
}

static void test_strscpy(void) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpy(target, space_left, "12345");

        assert(streq(target, "12345"));
        assert(space_left == 20);
}

static void test_strscpyl(void) {
        char target[25];
        size_t space_left;

        space_left = sizeof(target);
        space_left = strscpyl(target, space_left, "12345", "waldo", "waldo", NULL);

        assert(streq(target, "12345waldowaldo"));
        assert(space_left == 10);
}

int main(int argc, char *argv[]) {
        test_strpcpy();
        test_strpcpyf();
        test_strpcpyl();
        test_strscpy();
        test_strscpyl();

        return 0;
}
