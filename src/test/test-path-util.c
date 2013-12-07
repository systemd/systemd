/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <stdio.h>

#include "path-util.h"
#include "util.h"
#include "macro.h"


static void test_path(void) {
        assert_se(path_equal("/goo", "/goo"));
        assert_se(path_equal("//goo", "/goo"));
        assert_se(path_equal("//goo/////", "/goo"));
        assert_se(path_equal("goo/////", "goo"));

        assert_se(path_equal("/goo/boo", "/goo//boo"));
        assert_se(path_equal("//goo/boo", "/goo/boo//"));

        assert_se(path_equal("/", "///"));

        assert_se(!path_equal("/x", "x/"));
        assert_se(!path_equal("x/", "/"));

        assert_se(!path_equal("/x/./y", "x/y"));
        assert_se(!path_equal("x/.y", "x/y"));

        assert_se(path_is_absolute("/"));
        assert_se(!path_is_absolute("./"));

        assert_se(is_path("/dir"));
        assert_se(is_path("a/b"));
        assert_se(!is_path("."));

        assert_se(streq(basename("./aa/bb/../file.da."), "file.da."));
        assert_se(streq(basename("/aa///.file"), ".file"));
        assert_se(streq(basename("/aa///file..."), "file..."));
        assert_se(streq(basename("file.../"), ""));

#define test_parent(x, y) {                                \
                char _cleanup_free_ *z = NULL;             \
                int r = path_get_parent(x, &z);            \
                printf("expected: %s\n", y ? y : "error"); \
                printf("actual: %s\n", r<0 ? "error" : z); \
                assert_se((y==NULL) ^ (r==0));             \
                assert_se(y==NULL || path_equal(z, y));    \
        }

        test_parent("./aa/bb/../file.da.", "./aa/bb/..");
        test_parent("/aa///.file", "/aa///");
        test_parent("/aa///file...", "/aa///");
        test_parent("file.../", NULL);

        assert_se(path_is_mount_point("/", true));
        assert_se(path_is_mount_point("/", false));

        {
                char p1[] = "aaa/bbb////ccc";
                char p2[] = "//aaa/.////ccc";
                char p3[] = "/./";

                assert(path_equal(path_kill_slashes(p1), "aaa/bbb/ccc"));
                assert(path_equal(path_kill_slashes(p2), "/aaa/./ccc"));
                assert(path_equal(path_kill_slashes(p3), "/./"));
        }
}

static void test_find_binary(void) {
        char *p;

        assert(find_binary("/bin/sh", &p) == 0);
        puts(p);
        assert(streq(p, "/bin/sh"));
        free(p);

        assert(find_binary("./test-path-util", &p) == 0);
        puts(p);
        assert(endswith(p, "/test-path-util"));
        assert(path_is_absolute(p));
        free(p);

        assert(find_binary("sh", &p) == 0);
        puts(p);
        assert(endswith(p, "/sh"));
        assert(path_is_absolute(p));
        free(p);

        assert(find_binary("xxxx-xxxx", &p) == -ENOENT);
}

static void test_prefixes(void) {
        static const char* values[] = { "/a/b/c/d", "/a/b/c", "/a/b", "/a", "", NULL};
        unsigned i;
        char s[PATH_MAX];
        bool b;

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "/a/b/c/d") {
                log_error("---%s---", s);
                assert_se(streq(s, values[i++]));
        }
        assert_se(values[i] == NULL);

        i = 1;
        PATH_FOREACH_PREFIX(s, "/a/b/c/d") {
                log_error("---%s---", s);
                assert_se(streq(s, values[i++]));
        }
        assert_se(values[i] == NULL);

        i = 0;
        PATH_FOREACH_PREFIX_MORE(s, "////a////b////c///d///////")
                assert_se(streq(s, values[i++]));
        assert_se(values[i] == NULL);

        i = 1;
        PATH_FOREACH_PREFIX(s, "////a////b////c///d///////")
                assert_se(streq(s, values[i++]));
        assert_se(values[i] == NULL);

        PATH_FOREACH_PREFIX(s, "////")
                assert_not_reached("Wut?");

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "////") {
                assert_se(!b);
                assert_se(streq(s, ""));
                b = true;
        }
        assert_se(b);

        PATH_FOREACH_PREFIX(s, "")
                assert_not_reached("wut?");

        b = false;
        PATH_FOREACH_PREFIX_MORE(s, "") {
                assert(!b);
                assert(streq(s, ""));
                b = true;
        }
}

int main(void) {
        test_path();
        test_find_binary();
        test_prefixes();
        return 0;
}
