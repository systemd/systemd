/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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


#include "log.h"
#include "bus-signature.h"
#include "bus-internal.h"

int main(int argc, char *argv[]) {
        char prefix[256];
        int r;

        assert_se(signature_is_single("y", false));
        assert_se(signature_is_single("u", false));
        assert_se(signature_is_single("v", false));
        assert_se(signature_is_single("as", false));
        assert_se(signature_is_single("(ss)", false));
        assert_se(signature_is_single("()", false));
        assert_se(signature_is_single("(()()()()())", false));
        assert_se(signature_is_single("(((())))", false));
        assert_se(signature_is_single("((((s))))", false));
        assert_se(signature_is_single("{ss}", true));
        assert_se(signature_is_single("a{ss}", false));
        assert_se(!signature_is_single("uu", false));
        assert_se(!signature_is_single("", false));
        assert_se(!signature_is_single("(", false));
        assert_se(!signature_is_single(")", false));
        assert_se(!signature_is_single("())", false));
        assert_se(!signature_is_single("((())", false));
        assert_se(!signature_is_single("{)", false));
        assert_se(!signature_is_single("{}", true));
        assert_se(!signature_is_single("{sss}", true));
        assert_se(!signature_is_single("{s}", true));
        assert_se(!signature_is_single("{ss}", false));
        assert_se(!signature_is_single("{ass}", true));
        assert_se(!signature_is_single("a}", true));

        assert_se(signature_is_pair("yy"));
        assert_se(signature_is_pair("ss"));
        assert_se(signature_is_pair("sas"));
        assert_se(signature_is_pair("sv"));
        assert_se(signature_is_pair("sa(vs)"));
        assert_se(!signature_is_pair(""));
        assert_se(!signature_is_pair("va"));
        assert_se(!signature_is_pair("sss"));
        assert_se(!signature_is_pair("{s}ss"));

        assert_se(signature_is_valid("ssa{ss}sssub", true));
        assert_se(signature_is_valid("ssa{ss}sssub", false));
        assert_se(signature_is_valid("{ss}", true));
        assert_se(!signature_is_valid("{ss}", false));
        assert_se(signature_is_valid("", true));
        assert_se(signature_is_valid("", false));

        assert_se(signature_is_valid("sssusa(uuubbba(uu)uuuu)a{u(uuuvas)}", false));

        assert_se(!signature_is_valid("a", false));
        assert_se(signature_is_valid("as", false));
        assert_se(signature_is_valid("aas", false));
        assert_se(signature_is_valid("aaas", false));
        assert_se(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", false));
        assert_se(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaas", false));
        assert_se(!signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaau", false));

        assert_se(signature_is_valid("(((((((((((((((((((((((((((((((())))))))))))))))))))))))))))))))", false));
        assert_se(!signature_is_valid("((((((((((((((((((((((((((((((((()))))))))))))))))))))))))))))))))", false));

        assert_se(namespace_complex_pattern("", ""));
        assert_se(namespace_complex_pattern("foobar", "foobar"));
        assert_se(namespace_complex_pattern("foobar.waldo", "foobar.waldo"));
        assert_se(namespace_complex_pattern("foobar.", "foobar.waldo"));
        assert_se(namespace_complex_pattern("foobar.waldo", "foobar."));
        assert_se(!namespace_complex_pattern("foobar.waldo", "foobar"));
        assert_se(!namespace_complex_pattern("foobar", "foobar.waldo"));
        assert_se(!namespace_complex_pattern("", "foo"));
        assert_se(!namespace_complex_pattern("foo", ""));
        assert_se(!namespace_complex_pattern("foo.", ""));

        assert_se(path_complex_pattern("", ""));
        assert_se(!path_complex_pattern("", "/"));
        assert_se(!path_complex_pattern("/", ""));
        assert_se(path_complex_pattern("/", "/"));
        assert_se(path_complex_pattern("/foobar/", "/"));
        assert_se(!path_complex_pattern("/foobar/", "/foobar"));
        assert_se(path_complex_pattern("/foobar", "/foobar"));
        assert_se(!path_complex_pattern("/foobar", "/foobar/"));
        assert_se(!path_complex_pattern("/foobar", "/foobar/waldo"));
        assert_se(path_complex_pattern("/foobar/", "/foobar/waldo"));
        assert_se(path_complex_pattern("/foobar/waldo", "/foobar/"));

        assert_se(path_simple_pattern("/foo/", "/foo/bar/waldo"));

        assert_se(namespace_simple_pattern("", ""));
        assert_se(namespace_simple_pattern("", ".foobar"));
        assert_se(namespace_simple_pattern("foobar", "foobar"));
        assert_se(namespace_simple_pattern("foobar.waldo", "foobar.waldo"));
        assert_se(namespace_simple_pattern("foobar", "foobar.waldo"));
        assert_se(!namespace_simple_pattern("foobar.waldo", "foobar"));
        assert_se(!namespace_simple_pattern("", "foo"));
        assert_se(!namespace_simple_pattern("foo", ""));
        assert_se(namespace_simple_pattern("foo.", "foo.bar.waldo"));

        assert_se(streq(object_path_startswith("/foo/bar", "/foo"), "bar"));
        assert_se(streq(object_path_startswith("/foo", "/foo"), ""));
        assert_se(streq(object_path_startswith("/foo", "/"), "foo"));
        assert_se(streq(object_path_startswith("/", "/"), ""));
        assert_se(!object_path_startswith("/foo", "/bar"));
        assert_se(!object_path_startswith("/", "/bar"));
        assert_se(!object_path_startswith("/foo", ""));

        assert_se(object_path_is_valid("/foo/bar"));
        assert_se(object_path_is_valid("/foo"));
        assert_se(object_path_is_valid("/"));
        assert_se(object_path_is_valid("/foo5"));
        assert_se(object_path_is_valid("/foo_5"));
        assert_se(!object_path_is_valid(""));
        assert_se(!object_path_is_valid("/foo/"));
        assert_se(!object_path_is_valid("//"));
        assert_se(!object_path_is_valid("//foo"));
        assert_se(!object_path_is_valid("/foo//bar"));
        assert_se(!object_path_is_valid("/foo/aaaäöä"));

        OBJECT_PATH_FOREACH_PREFIX(prefix, "/") {
                log_info("<%s>", prefix);
                assert_not_reached("???");
        }

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx") {
                log_info("<%s>", prefix);
                assert_se(streq(prefix, "/"));
                assert_se(r == 0);
                r++;
        }
        assert_se(r == 1);

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx/yyy/zzz") {
                log_info("<%s>", prefix);
                assert_se(r != 0 || streq(prefix, "/xxx/yyy"));
                assert_se(r != 1 || streq(prefix, "/xxx"));
                assert_se(r != 2 || streq(prefix, "/"));
                r++;
        }
        assert_se(r == 3);

        return 0;
}
