/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "macro.h"
#include "dns-domain.h"

static void test_dns_label_unescape_one(const char *what, const char *expect, size_t buffer_sz, int ret) {
        char buffer[buffer_sz];
        int r;

        r = dns_label_unescape(&what, buffer, buffer_sz);
        assert_se(r == ret);

        if (r < 0)
                return;

        assert_se(streq(buffer, expect));
}

static void test_dns_label_unescape(void) {
        test_dns_label_unescape_one("hallo", "hallo", 6, 5);
        test_dns_label_unescape_one("hallo", "hallo", 4, -ENOSPC);
        test_dns_label_unescape_one("", "", 10, 0);
        test_dns_label_unescape_one("hallo\\.foobar", "hallo.foobar", 20, 12);
        test_dns_label_unescape_one("hallo.foobar", "hallo", 10, 5);
        test_dns_label_unescape_one("hallo\n.foobar", "hallo", 20, -EINVAL);
        test_dns_label_unescape_one("hallo\\", "hallo", 20, -EINVAL);
        test_dns_label_unescape_one("hallo\\032 ", "hallo  ", 20, 7);
        test_dns_label_unescape_one(".", "", 20, 0);
        test_dns_label_unescape_one("..", "", 20, -EINVAL);
        test_dns_label_unescape_one(".foobar", "", 20, -EINVAL);
        test_dns_label_unescape_one("foobar.", "foobar", 20, 6);
}

static void test_dns_label_unescape_suffix_one(const char *what, const char *expect1, const char *expect2, size_t buffer_sz, int ret1, int ret2) {
        char buffer[buffer_sz];
        const char *label;
        int r;

        label = what + strlen(what);

        r = dns_label_unescape_suffix(what, &label, buffer, buffer_sz);
        assert_se(r == ret1);
        if (r >= 0)
                assert_se(streq(buffer, expect1));

        r = dns_label_unescape_suffix(what, &label, buffer, buffer_sz);
        assert_se(r == ret2);
        if (r >= 0)
                assert_se(streq(buffer, expect2));
}

static void test_dns_label_unescape_suffix(void) {
        test_dns_label_unescape_suffix_one("hallo", "hallo", "", 6, 5, 0);
        test_dns_label_unescape_suffix_one("hallo", "hallo", "", 4, -ENOSPC, -ENOSPC);
        test_dns_label_unescape_suffix_one("", "", "", 10, 0, 0);
        test_dns_label_unescape_suffix_one("hallo\\.foobar", "hallo.foobar", "", 20, 12, 0);
        test_dns_label_unescape_suffix_one("hallo.foobar", "foobar", "hallo", 10, 6, 5);
        test_dns_label_unescape_suffix_one("hallo.foobar\n", "foobar", "foobar", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_suffix_one("hallo\\", "hallo", "hallo", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_suffix_one("hallo\\032 ", "hallo  ", "", 20, 7, 0);
        test_dns_label_unescape_suffix_one(".", "", "", 20, 0, 0);
        test_dns_label_unescape_suffix_one("..", "", "", 20, 0, 0);
        test_dns_label_unescape_suffix_one(".foobar", "foobar", "", 20, 6, -EINVAL);
        test_dns_label_unescape_suffix_one("foobar.", "", "foobar", 20, 0, 6);
        test_dns_label_unescape_suffix_one("foo\\\\bar", "foo\\bar", "", 20, 7, 0);
        test_dns_label_unescape_suffix_one("foo.bar", "bar", "foo", 20, 3, 3);
        test_dns_label_unescape_suffix_one("foo..bar", "bar", "", 20, 3, -EINVAL);
        test_dns_label_unescape_suffix_one("foo...bar", "bar", "", 20, 3, -EINVAL);
        test_dns_label_unescape_suffix_one("foo\\.bar", "foo.bar", "", 20, 7, 0);
        test_dns_label_unescape_suffix_one("foo\\\\.bar", "bar", "foo\\", 20, 3, 4);
        test_dns_label_unescape_suffix_one("foo\\\\\\.bar", "foo\\.bar", "", 20, 8, 0);
}

static void test_dns_label_escape_one(const char *what, size_t l, const char *expect, int ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        r = dns_label_escape(what, l, &t);
        assert_se(r == ret);

        if (r < 0)
                return;

        assert_se(streq_ptr(expect, t));
}

static void test_dns_label_escape(void) {
        test_dns_label_escape_one("", 0, "", 0);
        test_dns_label_escape_one("hallo", 5, "hallo", 5);
        test_dns_label_escape_one("hallo", 6, NULL, -EINVAL);
        test_dns_label_escape_one("hallo hallo.foobar,waldi", 24, "hallo\\032hallo\\.foobar\\044waldi", 31);
}

static void test_dns_name_normalize_one(const char *what, const char *expect, int ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        r = dns_name_normalize(what, &t);
        assert_se(r == ret);

        if (r < 0)
                return;

        assert_se(streq_ptr(expect, t));
}

static void test_dns_name_normalize(void) {
        test_dns_name_normalize_one("", "", 0);
        test_dns_name_normalize_one("f", "f", 0);
        test_dns_name_normalize_one("f.waldi", "f.waldi", 0);
        test_dns_name_normalize_one("f \\032.waldi", "f\\032\\032.waldi", 0);
        test_dns_name_normalize_one("\\000", NULL, -EINVAL);
        test_dns_name_normalize_one("..", NULL, -EINVAL);
        test_dns_name_normalize_one(".foobar", NULL, -EINVAL);
        test_dns_name_normalize_one("foobar.", "foobar", 0);
        test_dns_name_normalize_one(".", "", 0);
}

static void test_dns_name_equal_one(const char *a, const char *b, int ret) {
        int r;

        r = dns_name_equal(a, b);
        assert_se(r == ret);

        r = dns_name_equal(b, a);
        assert_se(r == ret);
}

static void test_dns_name_equal(void) {
        test_dns_name_equal_one("", "", true);
        test_dns_name_equal_one("x", "x", true);
        test_dns_name_equal_one("x", "x.", true);
        test_dns_name_equal_one("abc.def", "abc.def", true);
        test_dns_name_equal_one("abc.def", "ABC.def", true);
        test_dns_name_equal_one("abc.def", "CBA.def", false);
        test_dns_name_equal_one("", "xxx", false);
        test_dns_name_equal_one("ab", "a", false);
        test_dns_name_equal_one("\\000", "xxxx", -EINVAL);
        test_dns_name_equal_one(".", "", true);
        test_dns_name_equal_one(".", ".", true);
        test_dns_name_equal_one("..", "..", -EINVAL);
}

static void test_dns_name_between_one(const char *a, const char *b, const char *c, int ret) {
        int r;

        r = dns_name_between(a, b, c);
        assert_se(r == ret);

        r = dns_name_between(c, b, a);
        if (ret >= 0)
                assert_se(r == 0);
        else
                assert_se(r == ret);
}

static void test_dns_name_between(void) {
        /* see https://tools.ietf.org/html/rfc4034#section-6.1
           Note that we use "\033.z.example" in stead of "\001.z.example" as we
           consider the latter invalid */
        test_dns_name_between_one("example", "a.example", "yljkjljk.a.example", true);
        test_dns_name_between_one("a.example", "yljkjljk.a.example", "Z.a.example", true);
        test_dns_name_between_one("yljkjljk.a.example", "Z.a.example", "zABC.a.EXAMPLE", true);
        test_dns_name_between_one("Z.a.example", "zABC.a.EXAMPLE", "z.example", true);
        test_dns_name_between_one("zABC.a.EXAMPLE", "z.example", "\\033.z.example", true);
        test_dns_name_between_one("z.example", "\\033.z.example", "*.z.example", true);
        test_dns_name_between_one("\\033.z.example", "*.z.example", "\\200.z.example", true);
        test_dns_name_between_one("*.z.example", "\\200.z.example", "example", true);
        test_dns_name_between_one("\\200.z.example", "example", "a.example", true);

        test_dns_name_between_one("example", "a.example", "example", -EINVAL);
        test_dns_name_between_one("example", "example", "yljkjljk.a.example", false);
        test_dns_name_between_one("example", "yljkjljk.a.example", "yljkjljk.a.example", false);
}

static void test_dns_name_endswith_one(const char *a, const char *b, int ret) {
        assert_se(dns_name_endswith(a, b) == ret);
}

static void test_dns_name_endswith(void) {
        test_dns_name_endswith_one("", "", true);
        test_dns_name_endswith_one("", "xxx", false);
        test_dns_name_endswith_one("xxx", "", true);
        test_dns_name_endswith_one("x", "x", true);
        test_dns_name_endswith_one("x", "y", false);
        test_dns_name_endswith_one("x.y", "y", true);
        test_dns_name_endswith_one("x.y", "Y", true);
        test_dns_name_endswith_one("x.y", "x", false);
        test_dns_name_endswith_one("x.y.z", "Z", true);
        test_dns_name_endswith_one("x.y.z", "y.Z", true);
        test_dns_name_endswith_one("x.y.z", "x.y.Z", true);
        test_dns_name_endswith_one("x.y.z", "waldo", false);
        test_dns_name_endswith_one("x.y.z.u.v.w", "y.z", false);
        test_dns_name_endswith_one("x.y.z.u.v.w", "u.v.w", true);
        test_dns_name_endswith_one("x.y\001.z", "waldo", -EINVAL);
}

static void test_dns_name_root(void) {
        assert_se(dns_name_root("") == true);
        assert_se(dns_name_root(".") == true);
        assert_se(dns_name_root("xxx") == false);
        assert_se(dns_name_root("xxx.") == false);
        assert_se(dns_name_root("..") == -EINVAL);
}

static void test_dns_name_single_label(void) {
        assert_se(dns_name_single_label("") == false);
        assert_se(dns_name_single_label(".") == false);
        assert_se(dns_name_single_label("..") == -EINVAL);
        assert_se(dns_name_single_label("x") == true);
        assert_se(dns_name_single_label("x.") == true);
        assert_se(dns_name_single_label("xx.yy") == false);
}

static void test_dns_name_reverse_one(const char *address, const char *name) {
        _cleanup_free_ char *p = NULL;
        union in_addr_union a, b = {};
        int familya, familyb;

        assert_se(in_addr_from_string_auto(address, &familya, &a) >= 0);
        assert_se(dns_name_reverse(familya, &a, &p) >= 0);
        assert_se(streq(p, name));
        assert_se(dns_name_address(p, &familyb, &b) > 0);
        assert_se(familya == familyb);
        assert_se(in_addr_equal(familya, &a, &b));
}

static void test_dns_name_reverse(void) {
        test_dns_name_reverse_one("47.11.8.15", "15.8.11.47.in-addr.arpa");
        test_dns_name_reverse_one("fe80::47", "7.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa");
        test_dns_name_reverse_one("127.0.0.1", "1.0.0.127.in-addr.arpa");
        test_dns_name_reverse_one("::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
}

static void test_dns_name_concat_one(const char *a, const char *b, int r, const char *result) {
        _cleanup_free_ char *p = NULL;

        assert_se(dns_name_concat(a, b, &p) == r);
        assert_se(streq_ptr(p, result));
}

static void test_dns_name_concat(void) {
        test_dns_name_concat_one("foo", "bar", 0, "foo.bar");
        test_dns_name_concat_one("foo.foo", "bar.bar", 0, "foo.foo.bar.bar");
        test_dns_name_concat_one("foo", NULL, 0, "foo");
        test_dns_name_concat_one("foo.", "bar.", 0, "foo.bar");
}

static void test_dns_name_is_valid_one(const char *s, int ret) {
        assert_se(dns_name_is_valid(s) == ret);
}

static void test_dns_name_is_valid(void) {
        test_dns_name_is_valid_one("foo", 1);
        test_dns_name_is_valid_one("foo.", 1);
        test_dns_name_is_valid_one("Foo", 1);
        test_dns_name_is_valid_one("foo.bar", 1);
        test_dns_name_is_valid_one("foo.bar.baz", 1);
        test_dns_name_is_valid_one("", 1);
        test_dns_name_is_valid_one("foo..bar", 0);
        test_dns_name_is_valid_one(".foo.bar", 0);
        test_dns_name_is_valid_one("foo.bar.", 1);
        test_dns_name_is_valid_one("\\zbar", 0);
        test_dns_name_is_valid_one("ä", 1);
        test_dns_name_is_valid_one("\n", 0);
}

int main(int argc, char *argv[]) {

        test_dns_label_unescape();
        test_dns_label_unescape_suffix();
        test_dns_label_escape();
        test_dns_name_normalize();
        test_dns_name_equal();
        test_dns_name_endswith();
        test_dns_name_between();
        test_dns_name_root();
        test_dns_name_single_label();
        test_dns_name_reverse();
        test_dns_name_concat();
        test_dns_name_is_valid();

        return 0;
}
