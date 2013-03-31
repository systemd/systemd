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

#include <assert.h>
#include <stdlib.h>

#include "log.h"
#include "bus-signature.h"
#include "bus-internal.h"

int main(int argc, char *argv[]) {

        assert_se(signature_is_single("y"));
        assert_se(signature_is_single("u"));
        assert_se(signature_is_single("v"));
        assert_se(signature_is_single("as"));
        assert_se(signature_is_single("(ss)"));
        assert_se(signature_is_single("()"));
        assert_se(signature_is_single("(()()()()())"));
        assert_se(signature_is_single("(((())))"));
        assert_se(signature_is_single("((((s))))"));
        assert_se(signature_is_single("{ss}"));
        assert_se(signature_is_single("a{ss}"));
        assert_se(!signature_is_single("uu"));
        assert_se(!signature_is_single(""));
        assert_se(!signature_is_single("("));
        assert_se(!signature_is_single(")"));
        assert_se(!signature_is_single("())"));
        assert_se(!signature_is_single("((())"));
        assert_se(!signature_is_single("{)"));
        assert_se(!signature_is_single("{}"));
        assert_se(!signature_is_single("{sss}"));
        assert_se(!signature_is_single("{s}"));
        assert_se(!signature_is_single("{ass}"));
        assert_se(!signature_is_single("a}"));

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
        assert_se(path_complex_pattern("", "/"));
        assert_se(path_complex_pattern("/", ""));
        assert_se(path_complex_pattern("/", "/"));
        assert_se(path_complex_pattern("/foobar/", "/"));
        assert_se(path_complex_pattern("/foobar/", "/foobar"));
        assert_se(path_complex_pattern("/foobar", "/foobar"));
        assert_se(path_complex_pattern("/foobar", "/foobar/"));
        assert_se(!path_complex_pattern("/foobar", "/foobar/waldo"));
        assert_se(path_complex_pattern("/foobar/", "/foobar/waldo"));

        assert_se(namespace_simple_pattern("", ""));
        assert_se(namespace_simple_pattern("foobar", "foobar"));
        assert_se(namespace_simple_pattern("foobar.waldo", "foobar.waldo"));
        assert_se(namespace_simple_pattern("foobar", "foobar.waldo"));
        assert_se(!namespace_simple_pattern("foobar.waldo", "foobar"));
        assert_se(!namespace_simple_pattern("", "foo"));
        assert_se(!namespace_simple_pattern("foo", ""));

        return 0;
}
