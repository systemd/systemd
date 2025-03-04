/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"

static void test_dns_label_unescape_one(const char *what, const char *expect, size_t buffer_sz, int ret, int ret_ldh) {
        char buffer[buffer_sz];
        int r;
        const char *w = what;

        log_info("%s, %s, %zu, →%d/%d", what, expect, buffer_sz, ret, ret_ldh);

        r = dns_label_unescape(&w, buffer, buffer_sz, 0);
        assert_se(r == ret);
        if (r >= 0)
                ASSERT_STREQ(buffer, expect);

        w = what;
        r = dns_label_unescape(&w, buffer, buffer_sz, DNS_LABEL_LDH);
        assert_se(r == ret_ldh);
        if (r >= 0)
                ASSERT_STREQ(buffer, expect);

        w = what;
        r = dns_label_unescape(&w, buffer, buffer_sz, DNS_LABEL_NO_ESCAPES);
        const int ret_noe = strchr(what, '\\') ? -EINVAL : ret;
        assert_se(r == ret_noe);
        if (r >= 0)
                ASSERT_STREQ(buffer, expect);
}

TEST(dns_label_unescape) {
        test_dns_label_unescape_one("hallo", "hallo", 6, 5, 5);
        test_dns_label_unescape_one("hallo", "hallo", 4, -ENOBUFS, -ENOBUFS);
        test_dns_label_unescape_one("", "", 10, 0, 0);
        test_dns_label_unescape_one("hallo\\.foobar", "hallo.foobar", 20, 12, -EINVAL);
        test_dns_label_unescape_one("hallo.foobar", "hallo", 10, 5, 5);
        test_dns_label_unescape_one("hallo\n.foobar", "hallo", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_one("hallo\\", "hallo", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_one("hallo\\032 ", "hallo  ", 20, 7, -EINVAL);
        test_dns_label_unescape_one(".", "", 20, 0, 0);
        test_dns_label_unescape_one("..", "", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_one(".foobar", "", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_one("foobar.", "foobar", 20, 6, 6);
        test_dns_label_unescape_one("foobar..", "foobar", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_one("foo-bar", "foo-bar", 20, 7, 7);
        test_dns_label_unescape_one("foo-", "foo-", 20, 4, -EINVAL);
        test_dns_label_unescape_one("-foo", "-foo", 20, 4, -EINVAL);
        test_dns_label_unescape_one("-foo-", "-foo-", 20, 5, -EINVAL);
        test_dns_label_unescape_one("foo-.", "foo-", 20, 4, -EINVAL);
        test_dns_label_unescape_one("foo.-", "foo", 20, 3, 3);
        test_dns_label_unescape_one("foo\\032", "foo ", 20, 4, -EINVAL);
        test_dns_label_unescape_one("foo\\045", "foo-", 20, 4, -EINVAL);
        test_dns_label_unescape_one("głąb", "głąb", 20, 6, -EINVAL);
}

static void test_dns_name_to_wire_format_one(const char *what, const char *expect, size_t buffer_sz, int ret) {
        uint8_t buffer[buffer_sz];
        int r;

        log_info("%s, %s, %zu, →%d", what, strnull(expect), buffer_sz, ret);

        r = dns_name_to_wire_format(what, buffer, buffer_sz, false);
        assert_se(r == ret);

        if (r >= 0) {
                assert(expect);  /* for gcc */
                assert_se(memcmp(buffer, expect, r) == 0);
        }
}

TEST(dns_name_to_wire_format) {
        static const char out0[] = { 0 };
        static const char out1[] = { 3, 'f', 'o', 'o', 0 };
        static const char out2[] = { 5, 'h', 'a', 'l', 'l', 'o', 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
        static const char out3[] = { 4, ' ', 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
        static const char out4[] = { 9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     3, 'a', '1', '2', 0 };

        test_dns_name_to_wire_format_one("", out0, sizeof(out0), sizeof(out0));

        test_dns_name_to_wire_format_one("foo", out1, sizeof(out1), sizeof(out1));
        test_dns_name_to_wire_format_one("foo", out1, sizeof(out1) + 1, sizeof(out1));
        test_dns_name_to_wire_format_one("foo", out1, sizeof(out1) - 1, -ENOBUFS);

        test_dns_name_to_wire_format_one("hallo.foo.bar", out2, sizeof(out2), sizeof(out2));
        test_dns_name_to_wire_format_one("hallo.foo..bar", NULL, 32, -EINVAL);

        test_dns_name_to_wire_format_one("\\032foo.bar", out3, sizeof(out3), sizeof(out3));

        test_dns_name_to_wire_format_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a123", NULL, 500, -EINVAL);
        test_dns_name_to_wire_format_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12", out4, sizeof(out4), sizeof(out4));
}

static void test_dns_name_from_wire_format_one(const char *expect, const uint8_t *what, size_t len, int ret) {
        _cleanup_free_ char *name = NULL;
        int r;

        log_info("%s, %s, %zu, →%d", what, strnull(expect), len, ret);

        r = dns_name_from_wire_format(&what, &len, &name);
        assert_se(r == ret);

        if (r >= 0) {
                assert(expect);  /* for gcc */
                assert_se(memcmp(name, expect, r) == 0);
        }
}

TEST(dns_name_from_wire_format) {
        static const uint8_t in0[] = { 0 };
        static const uint8_t in1[] = { 3, 'f', 'o', 'o', 0 };
        static const uint8_t in2[] = { 5, 'h', 'a', 'l', 'l', 'o', 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
        static const uint8_t in2_1[] = { 5, 'h', 'a', 'l', 'l', 'o', 3, 'f', 'o', 'o', 0, 'b', 'a', 'r', 0 };
        static const uint8_t in3[] = { 4, ' ', 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
        static const uint8_t in4[] = { 9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     3, 'a', '1', '2', 0 }; /* 255 octets */
        static const uint8_t in5[] = { 9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     9, 'a', '1', '2', '3', '4', '5', '6', '7', '8',
                                     3, 'a', '1', '2', 0 }; /* 265 octets */

        test_dns_name_from_wire_format_one("", in0, sizeof(in0), strlen(""));

        test_dns_name_from_wire_format_one("foo", in1, sizeof(in1), strlen("foo"));
        test_dns_name_from_wire_format_one("foo", in1, sizeof(in1) - 1, strlen("foo"));

        test_dns_name_from_wire_format_one("hallo.foo.bar", in2, sizeof(in2), strlen("hallo.foo.bar"));
        test_dns_name_from_wire_format_one("hallo.foo", in2_1, sizeof(in2_1), strlen("hallo.foo"));

        test_dns_name_from_wire_format_one("\\032foo.bar", in3, sizeof(in3), strlen("\\032foo.bar"));

        test_dns_name_from_wire_format_one(NULL, in5, sizeof(in5), -EMSGSIZE);
        test_dns_name_from_wire_format_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12", in4, sizeof(in4), 253);
}

static void test_dns_label_unescape_suffix_one(const char *what, const char *expect1, const char *expect2, size_t buffer_sz, int ret1, int ret2) {
        char buffer[buffer_sz];
        const char *label;
        int r;

        log_info("%s, %s, %s, %zu, %d, %d", what, expect1, expect2, buffer_sz, ret1, ret2);

        label = what + strlen(what);

        r = dns_label_unescape_suffix(what, &label, buffer, buffer_sz);
        assert_se(r == ret1);
        if (r >= 0)
                ASSERT_STREQ(buffer, expect1);

        r = dns_label_unescape_suffix(what, &label, buffer, buffer_sz);
        assert_se(r == ret2);
        if (r >= 0)
                ASSERT_STREQ(buffer, expect2);
}

TEST(dns_label_unescape_suffix) {
        test_dns_label_unescape_suffix_one("hallo", "hallo", "", 6, 5, 0);
        test_dns_label_unescape_suffix_one("hallo", "hallo", "", 4, -ENOBUFS, -ENOBUFS);
        test_dns_label_unescape_suffix_one("", "", "", 10, 0, 0);
        test_dns_label_unescape_suffix_one("hallo\\.foobar", "hallo.foobar", "", 20, 12, 0);
        test_dns_label_unescape_suffix_one("hallo.foobar", "foobar", "hallo", 10, 6, 5);
        test_dns_label_unescape_suffix_one("hallo.foobar\n", "foobar", "foobar", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_suffix_one("hallo\\", "hallo", "hallo", 20, -EINVAL, -EINVAL);
        test_dns_label_unescape_suffix_one("hallo\\032 ", "hallo  ", "", 20, 7, 0);
        test_dns_label_unescape_suffix_one(".", "", "", 20, 0, 0);
        test_dns_label_unescape_suffix_one("..", "", "", 20, 0, -EINVAL);
        test_dns_label_unescape_suffix_one(".foobar", "foobar", "", 20, 6, -EINVAL);
        test_dns_label_unescape_suffix_one("foobar.", "foobar", "", 20, 6, 0);
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

        log_info("%s, %zu, %s, →%d", what, l, strnull(expect), ret);

        r = dns_label_escape_new(what, l, &t);
        assert_se(r == ret);

        if (r < 0)
                return;

        ASSERT_STREQ(expect, t);
}

TEST(dns_label_escape) {
        test_dns_label_escape_one("", 0, NULL, -EINVAL);
        test_dns_label_escape_one("hallo", 5, "hallo", 5);
        test_dns_label_escape_one("hallo", 6, "hallo\\000", 9);
        test_dns_label_escape_one("hallo hallo.foobar,waldi", 24, "hallo\\032hallo\\.foobar\\044waldi", 31);
}

static void test_dns_name_normalize_one(const char *what, const char *expect, int ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        r = dns_name_normalize(what, 0, &t);
        assert_se(r == ret);

        if (r < 0)
                return;

        ASSERT_STREQ(expect, t);
}

TEST(dns_name_normalize) {
        test_dns_name_normalize_one("", ".", 0);
        test_dns_name_normalize_one("f", "f", 0);
        test_dns_name_normalize_one("f.waldi", "f.waldi", 0);
        test_dns_name_normalize_one("f \\032.waldi", "f\\032\\032.waldi", 0);
        test_dns_name_normalize_one("\\000", "\\000", 0);
        test_dns_name_normalize_one("..", NULL, -EINVAL);
        test_dns_name_normalize_one(".foobar", NULL, -EINVAL);
        test_dns_name_normalize_one("foobar.", "foobar", 0);
        test_dns_name_normalize_one(".", ".", 0);
}

static void test_dns_name_equal_one(const char *a, const char *b, int ret) {
        int r;

        r = dns_name_equal(a, b);
        assert_se(r == ret);

        r = dns_name_equal(b, a);
        assert_se(r == ret);
}

TEST(dns_name_equal) {
        test_dns_name_equal_one("", "", true);
        test_dns_name_equal_one("x", "x", true);
        test_dns_name_equal_one("x", "x.", true);
        test_dns_name_equal_one("abc.def", "abc.def", true);
        test_dns_name_equal_one("abc.def", "ABC.def", true);
        test_dns_name_equal_one("abc.def", "CBA.def", false);
        test_dns_name_equal_one("", "xxx", false);
        test_dns_name_equal_one("ab", "a", false);
        test_dns_name_equal_one("\\000", "\\000", true);
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
                assert_se(r == 0 || dns_name_equal(a, c) > 0);
        else
                assert_se(r == ret);
}

TEST(dns_name_between) {
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

        test_dns_name_between_one("example", "a.example", "example", true);
        test_dns_name_between_one("example", "example", "example", false);
        test_dns_name_between_one("example", "example", "yljkjljk.a.example", false);
        test_dns_name_between_one("example", "yljkjljk.a.example", "yljkjljk.a.example", false);
        test_dns_name_between_one("hkps.pool.sks-keyservers.net", "_pgpkey-https._tcp.hkps.pool.sks-keyservers.net", "ipv4.pool.sks-keyservers.net", true);
}

static void test_dns_name_endswith_one(const char *a, const char *b, int ret) {
        assert_se(dns_name_endswith(a, b) == ret);
}

TEST(dns_name_endswith) {
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

static void test_dns_name_startswith_one(const char *a, const char *b, int ret) {
        assert_se(dns_name_startswith(a, b) == ret);
}

TEST(dns_name_startswith) {
        test_dns_name_startswith_one("", "", true);
        test_dns_name_startswith_one("", "xxx", false);
        test_dns_name_startswith_one("xxx", "", true);
        test_dns_name_startswith_one("x", "x", true);
        test_dns_name_startswith_one("x", "y", false);
        test_dns_name_startswith_one("x.y", "x.y", true);
        test_dns_name_startswith_one("x.y", "y.x", false);
        test_dns_name_startswith_one("x.y", "x", true);
        test_dns_name_startswith_one("x.y", "X", true);
        test_dns_name_startswith_one("x.y", "y", false);
        test_dns_name_startswith_one("x.y", "", true);
        test_dns_name_startswith_one("x.y", "X", true);
}

TEST(dns_name_is_root) {
        assert_se(dns_name_is_root(""));
        assert_se(dns_name_is_root("."));
        assert_se(!dns_name_is_root("xxx"));
        assert_se(!dns_name_is_root("xxx."));
        assert_se(!dns_name_is_root(".."));
}

TEST(dns_name_is_single_label) {
        assert_se(!dns_name_is_single_label(""));
        assert_se(!dns_name_is_single_label("."));
        assert_se(!dns_name_is_single_label(".."));
        assert_se(dns_name_is_single_label("x"));
        assert_se(dns_name_is_single_label("x."));
        assert_se(!dns_name_is_single_label("xx.yy"));
}

static void test_dns_name_reverse_one(const char *address, const char *name) {
        _cleanup_free_ char *p = NULL;
        union in_addr_union a, b = {};
        int familya, familyb;

        assert_se(in_addr_from_string_auto(address, &familya, &a) >= 0);
        assert_se(dns_name_reverse(familya, &a, &p) >= 0);
        ASSERT_STREQ(p, name);
        assert_se(dns_name_address(p, &familyb, &b) > 0);
        assert_se(familya == familyb);
        assert_se(in_addr_equal(familya, &a, &b));
}

TEST(dns_name_reverse) {
        test_dns_name_reverse_one("47.11.8.15", "15.8.11.47.in-addr.arpa");
        test_dns_name_reverse_one("fe80::47", "7.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa");
        test_dns_name_reverse_one("127.0.0.1", "1.0.0.127.in-addr.arpa");
        test_dns_name_reverse_one("::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
}

static void test_dns_name_concat_one(const char *a, const char *b, int r, const char *result) {
        _cleanup_free_ char *p = NULL;

        assert_se(dns_name_concat(a, b, 0, &p) == r);
        ASSERT_STREQ(p, result);
}

TEST(dns_name_concat) {
        test_dns_name_concat_one("", "", 0, ".");
        test_dns_name_concat_one(".", "", 0, ".");
        test_dns_name_concat_one("", ".", 0, ".");
        test_dns_name_concat_one(".", ".", 0, ".");
        test_dns_name_concat_one("foo", "bar", 0, "foo.bar");
        test_dns_name_concat_one("foo.foo", "bar.bar", 0, "foo.foo.bar.bar");
        test_dns_name_concat_one("foo", NULL, 0, "foo");
        test_dns_name_concat_one("foo", ".", 0, "foo");
        test_dns_name_concat_one("foo.", "bar.", 0, "foo.bar");
        test_dns_name_concat_one(NULL, NULL, 0, ".");
        test_dns_name_concat_one(NULL, ".", 0, ".");
        test_dns_name_concat_one(NULL, "foo", 0, "foo");
}

static void test_dns_name_is_valid_one(const char *s, int ret, int ret_ldh) {
        log_info("%s, →%d", s, ret);

        assert_se(dns_name_is_valid(s) == ret);
        assert_se(dns_name_is_valid_ldh(s) == ret_ldh);
}

TEST(dns_name_is_valid) {
        test_dns_name_is_valid_one("[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[._qotd._tcp.local", 1, 0);
        test_dns_name_is_valid_one("[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]._qotd._tcp.local", 0, 0);

        test_dns_name_is_valid_one("foo",               1, 1);
        test_dns_name_is_valid_one("foo.",              1, 1);
        test_dns_name_is_valid_one("foo..",             0, 0);
        test_dns_name_is_valid_one("Foo",               1, 1);
        test_dns_name_is_valid_one("foo.bar",           1, 1);
        test_dns_name_is_valid_one("foo.bar.baz",       1, 1);
        test_dns_name_is_valid_one("",                  1, 1);
        test_dns_name_is_valid_one("foo..bar",          0, 0);
        test_dns_name_is_valid_one(".foo.bar",          0, 0);
        test_dns_name_is_valid_one("foo.bar.",          1, 1);
        test_dns_name_is_valid_one("foo.bar..",         0, 0);
        test_dns_name_is_valid_one("\\zbar",            0, 0);
        test_dns_name_is_valid_one("ä",                 1, 0);
        test_dns_name_is_valid_one("\n",                0, 0);

        test_dns_name_is_valid_one("dash-",             1, 0);
        test_dns_name_is_valid_one("-dash",             1, 0);
        test_dns_name_is_valid_one("dash-dash",         1, 1);
        test_dns_name_is_valid_one("foo.dash-",         1, 0);
        test_dns_name_is_valid_one("foo.-dash",         1, 0);
        test_dns_name_is_valid_one("foo.dash-dash",     1, 1);
        test_dns_name_is_valid_one("foo.dash-.bar",     1, 0);
        test_dns_name_is_valid_one("foo.-dash.bar",     1, 0);
        test_dns_name_is_valid_one("foo.dash-dash.bar", 1, 1);
        test_dns_name_is_valid_one("dash-.bar",         1, 0);
        test_dns_name_is_valid_one("-dash.bar",         1, 0);
        test_dns_name_is_valid_one("dash-dash.bar",     1, 1);
        test_dns_name_is_valid_one("-.bar",             1, 0);
        test_dns_name_is_valid_one("foo.-",             1, 0);

        /* 256 characters */
        test_dns_name_is_valid_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345", 0, 0);

        /* 255 characters */
        test_dns_name_is_valid_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a1234", 0, 0);

        /* 254 characters */
        test_dns_name_is_valid_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a123", 0, 0);

        /* 253 characters */
        test_dns_name_is_valid_one("a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12345678.a12", 1, 1);

        /* label of 64 chars length */
        test_dns_name_is_valid_one("a123456789a123456789a123456789a123456789a123456789a123456789a123", 0, 0);

        /* label of 63 chars length */
        test_dns_name_is_valid_one("a123456789a123456789a123456789a123456789a123456789a123456789a12", 1, 1);
}

TEST(dns_service_name_is_valid) {
        assert_se(dns_service_name_is_valid("Lennart's Compüter"));
        assert_se(dns_service_name_is_valid("piff.paff"));

        assert_se(!dns_service_name_is_valid(NULL));
        assert_se(!dns_service_name_is_valid(""));
        assert_se(!dns_service_name_is_valid("foo\nbar"));
        assert_se(!dns_service_name_is_valid("foo\201bar"));
        assert_se(!dns_service_name_is_valid("this is an overly long string that is certainly longer than 63 characters"));
}

TEST(dns_srv_type_is_valid) {
        assert_se(dns_srv_type_is_valid("_http._tcp"));
        assert_se(dns_srv_type_is_valid("_foo-bar._tcp"));
        assert_se(dns_srv_type_is_valid("_w._udp"));
        assert_se(dns_srv_type_is_valid("_a800._tcp"));
        assert_se(dns_srv_type_is_valid("_a-800._tcp"));

        assert_se(!dns_srv_type_is_valid(NULL));
        assert_se(!dns_srv_type_is_valid(""));
        assert_se(!dns_srv_type_is_valid("x"));
        assert_se(!dns_srv_type_is_valid("_foo"));
        assert_se(!dns_srv_type_is_valid("_tcp"));
        assert_se(!dns_srv_type_is_valid("_"));
        assert_se(!dns_srv_type_is_valid("_foo."));
        assert_se(!dns_srv_type_is_valid("_föo._tcp"));
        assert_se(!dns_srv_type_is_valid("_f\no._tcp"));
        assert_se(!dns_srv_type_is_valid("_800._tcp"));
        assert_se(!dns_srv_type_is_valid("_-800._tcp"));
        assert_se(!dns_srv_type_is_valid("_-foo._tcp"));
        assert_se(!dns_srv_type_is_valid("_piep._foo._udp"));
}

TEST(dnssd_srv_type_is_valid) {
        assert_se(dnssd_srv_type_is_valid("_http._tcp"));
        assert_se(dnssd_srv_type_is_valid("_foo-bar._tcp"));
        assert_se(dnssd_srv_type_is_valid("_w._udp"));
        assert_se(dnssd_srv_type_is_valid("_a800._tcp"));
        assert_se(dnssd_srv_type_is_valid("_a-800._tcp"));

        assert_se(!dnssd_srv_type_is_valid(NULL));
        assert_se(!dnssd_srv_type_is_valid(""));
        assert_se(!dnssd_srv_type_is_valid("x"));
        assert_se(!dnssd_srv_type_is_valid("_foo"));
        assert_se(!dnssd_srv_type_is_valid("_tcp"));
        assert_se(!dnssd_srv_type_is_valid("_"));
        assert_se(!dnssd_srv_type_is_valid("_foo."));
        assert_se(!dnssd_srv_type_is_valid("_föo._tcp"));
        assert_se(!dnssd_srv_type_is_valid("_f\no._tcp"));
        assert_se(!dnssd_srv_type_is_valid("_800._tcp"));
        assert_se(!dnssd_srv_type_is_valid("_-800._tcp"));
        assert_se(!dnssd_srv_type_is_valid("_-foo._tcp"));
        assert_se(!dnssd_srv_type_is_valid("_piep._foo._udp"));
        assert_se(!dnssd_srv_type_is_valid("_foo._unknown"));
}

static void test_dns_service_join_one(const char *a, const char *b, const char *c, int r, const char *d) {
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *t = NULL;

        log_info("%s, %s, %s, →%d, %s", strnull(a), strnull(b), strnull(c), r, strnull(d));

        assert_se(dns_service_join(a, b, c, &t) == r);
        ASSERT_STREQ(t, d);

        if (r < 0)
                return;

        assert_se(dns_service_split(t, &x, &y, &z) >= 0);
        ASSERT_STREQ(a, x);
        ASSERT_STREQ(b, y);
        assert_se(dns_name_equal(c, z) > 0);
}

TEST(dns_service_join) {
        test_dns_service_join_one("", "", "", -EINVAL, NULL);
        test_dns_service_join_one("", "_http._tcp", "", -EINVAL, NULL);
        test_dns_service_join_one("", "_http._tcp", "foo", -EINVAL, NULL);
        test_dns_service_join_one("foo", "", "foo", -EINVAL, NULL);
        test_dns_service_join_one("foo", "foo", "foo", -EINVAL, NULL);

        test_dns_service_join_one("foo", "_http._tcp", "", 0, "foo._http._tcp");
        test_dns_service_join_one(NULL, "_http._tcp", "", 0, "_http._tcp");
        test_dns_service_join_one("foo", "_http._tcp", "foo", 0, "foo._http._tcp.foo");
        test_dns_service_join_one(NULL, "_http._tcp", "foo", 0, "_http._tcp.foo");
        test_dns_service_join_one("Lennart's PC", "_pc._tcp", "foo.bar.com", 0, "Lennart\\039s\\032PC._pc._tcp.foo.bar.com");
        test_dns_service_join_one(NULL, "_pc._tcp", "foo.bar.com", 0, "_pc._tcp.foo.bar.com");
}

static void test_dns_service_split_one(const char *joined, const char *a, const char *b, const char *c, int r) {
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *t = NULL;

        log_info("%s, %s, %s, %s, →%d", joined, strnull(a), strnull(b), strnull(c), r);

        assert_se(dns_service_split(joined, &x, &y, &z) == r);
        ASSERT_STREQ(x, a);
        ASSERT_STREQ(y, b);
        ASSERT_STREQ(z, c);

        if (r < 0)
                return;

        if (y) {
                assert_se(dns_service_join(x, y, z, &t) == 0);
                assert_se(dns_name_equal(joined, t) > 0);
        } else
                assert_se(!x && dns_name_equal(z, joined) > 0);
}

TEST(dns_service_split) {
        test_dns_service_split_one("", NULL, NULL, ".", 0);
        test_dns_service_split_one("foo", NULL, NULL, "foo", 0);
        test_dns_service_split_one("foo.bar", NULL, NULL, "foo.bar", 0);
        test_dns_service_split_one("_foo.bar", NULL, NULL, "_foo.bar", 0);
        test_dns_service_split_one("_foo._bar", NULL, "_foo._bar", ".", 0);
        test_dns_service_split_one("_meh._foo._bar", "_meh", "_foo._bar", ".", 0);
        test_dns_service_split_one("Wuff\\032Wuff._foo._bar.waldo.com", "Wuff Wuff", "_foo._bar", "waldo.com", 0);
        test_dns_service_split_one("_Q._Q-------------------------------------------------------------", NULL, "_Q._Q-------------------------------------------------------------", ".", 0);
}

static void test_dns_name_change_suffix_one(const char *name, const char *old_suffix, const char *new_suffix, int r, const char *result) {
        _cleanup_free_ char *s = NULL;

        log_info("%s, %s, %s, →%s", name, old_suffix, new_suffix, strnull(result));

        assert_se(dns_name_change_suffix(name, old_suffix, new_suffix, &s) == r);
        ASSERT_STREQ(s, result);
}

TEST(dns_name_change_suffix) {
        test_dns_name_change_suffix_one("foo.bar", "bar", "waldo", 1, "foo.waldo");
        test_dns_name_change_suffix_one("foo.bar.waldi.quux", "foo.bar.waldi.quux", "piff.paff", 1, "piff.paff");
        test_dns_name_change_suffix_one("foo.bar.waldi.quux", "bar.waldi.quux", "piff.paff", 1, "foo.piff.paff");
        test_dns_name_change_suffix_one("foo.bar.waldi.quux", "waldi.quux", "piff.paff", 1, "foo.bar.piff.paff");
        test_dns_name_change_suffix_one("foo.bar.waldi.quux", "quux", "piff.paff", 1, "foo.bar.waldi.piff.paff");
        test_dns_name_change_suffix_one("foo.bar.waldi.quux", "", "piff.paff", 1, "foo.bar.waldi.quux.piff.paff");
        test_dns_name_change_suffix_one("", "", "piff.paff", 1, "piff.paff");
        test_dns_name_change_suffix_one("", "", "", 1, ".");
        test_dns_name_change_suffix_one("a", "b", "c", 0, NULL);
}

static void test_dns_name_suffix_one(const char *name, unsigned n_labels, const char *result, int ret) {
        const char *p = NULL;

        log_info("%s, %u, → %s, %d", name, n_labels, strnull(result), ret);

        assert_se(ret == dns_name_suffix(name, n_labels, &p));
        ASSERT_STREQ(p, result);
}

TEST(dns_name_suffix) {
        test_dns_name_suffix_one("foo.bar", 2, "foo.bar", 0);
        test_dns_name_suffix_one("foo.bar", 1, "bar", 1);
        test_dns_name_suffix_one("foo.bar", 0, "", 2);
        test_dns_name_suffix_one("foo.bar", 3, NULL, -EINVAL);
        test_dns_name_suffix_one("foo.bar", 4, NULL, -EINVAL);

        test_dns_name_suffix_one("bar", 1, "bar", 0);
        test_dns_name_suffix_one("bar", 0, "", 1);
        test_dns_name_suffix_one("bar", 2, NULL, -EINVAL);
        test_dns_name_suffix_one("bar", 3, NULL, -EINVAL);

        test_dns_name_suffix_one("", 0, "", 0);
        test_dns_name_suffix_one("", 1, NULL, -EINVAL);
        test_dns_name_suffix_one("", 2, NULL, -EINVAL);
}

static void test_dns_name_count_labels_one(const char *name, int n) {
        log_info("%s, →%d", name, n);

        assert_se(dns_name_count_labels(name) == n);
}

TEST(dns_name_count_labels) {
        test_dns_name_count_labels_one("foo.bar.quux.", 3);
        test_dns_name_count_labels_one("foo.bar.quux", 3);
        test_dns_name_count_labels_one("foo.bar.", 2);
        test_dns_name_count_labels_one("foo.bar", 2);
        test_dns_name_count_labels_one("foo.", 1);
        test_dns_name_count_labels_one("foo", 1);
        test_dns_name_count_labels_one("", 0);
        test_dns_name_count_labels_one(".", 0);
        test_dns_name_count_labels_one("..", -EINVAL);
}

static void test_dns_name_equal_skip_one(const char *a, unsigned n_labels, const char *b, int ret) {
        log_info("%s, %u, %s, →%d", a, n_labels, b, ret);

        assert_se(dns_name_equal_skip(a, n_labels, b) == ret);
}

TEST(dns_name_equal_skip) {
        test_dns_name_equal_skip_one("foo", 0, "bar", 0);
        test_dns_name_equal_skip_one("foo", 0, "foo", 1);
        test_dns_name_equal_skip_one("foo", 1, "foo", 0);
        test_dns_name_equal_skip_one("foo", 2, "foo", 0);

        test_dns_name_equal_skip_one("foo.bar", 0, "foo.bar", 1);
        test_dns_name_equal_skip_one("foo.bar", 1, "foo.bar", 0);
        test_dns_name_equal_skip_one("foo.bar", 2, "foo.bar", 0);
        test_dns_name_equal_skip_one("foo.bar", 3, "foo.bar", 0);

        test_dns_name_equal_skip_one("foo.bar", 0, "bar", 0);
        test_dns_name_equal_skip_one("foo.bar", 1, "bar", 1);
        test_dns_name_equal_skip_one("foo.bar", 2, "bar", 0);
        test_dns_name_equal_skip_one("foo.bar", 3, "bar", 0);

        test_dns_name_equal_skip_one("foo.bar", 0, "", 0);
        test_dns_name_equal_skip_one("foo.bar", 1, "", 0);
        test_dns_name_equal_skip_one("foo.bar", 2, "", 1);
        test_dns_name_equal_skip_one("foo.bar", 3, "", 0);

        test_dns_name_equal_skip_one("", 0, "", 1);
        test_dns_name_equal_skip_one("", 1, "", 0);
        test_dns_name_equal_skip_one("", 1, "foo", 0);
        test_dns_name_equal_skip_one("", 2, "foo", 0);
}

TEST(dns_name_compare_func) {
        assert_se(dns_name_compare_func("", "") == 0);
        assert_se(dns_name_compare_func("", ".") == 0);
        assert_se(dns_name_compare_func(".", "") == 0);
        assert_se(dns_name_compare_func("foo", "foo.") == 0);
        assert_se(dns_name_compare_func("foo.", "foo") == 0);
        assert_se(dns_name_compare_func("foo", "foo") == 0);
        assert_se(dns_name_compare_func("foo.", "foo.") == 0);
        assert_se(dns_name_compare_func("heise.de", "HEISE.DE.") == 0);

        assert_se(dns_name_compare_func("de.", "heise.de") != 0);
}

static void test_dns_name_common_suffix_one(const char *a, const char *b, const char *result) {
        const char *c;

        log_info("%s, %s, →%s", a, b, result);

        assert_se(dns_name_common_suffix(a, b, &c) >= 0);
        ASSERT_STREQ(c, result);
}

TEST(dns_name_common_suffix) {
        test_dns_name_common_suffix_one("", "", "");
        test_dns_name_common_suffix_one("foo", "", "");
        test_dns_name_common_suffix_one("", "foo", "");
        test_dns_name_common_suffix_one("foo", "bar", "");
        test_dns_name_common_suffix_one("bar", "foo", "");
        test_dns_name_common_suffix_one("foo", "foo", "foo");
        test_dns_name_common_suffix_one("quux.foo", "foo", "foo");
        test_dns_name_common_suffix_one("foo", "quux.foo", "foo");
        test_dns_name_common_suffix_one("this.is.a.short.sentence", "this.is.another.short.sentence", "short.sentence");
        test_dns_name_common_suffix_one("FOO.BAR", "tEST.bAR", "BAR");
}

static void test_dns_name_apply_idna_one(const char *s, int expected, const char *result) {
        _cleanup_free_ char *buf = NULL;
        int r;

        r = dns_name_apply_idna(s, &buf);
        log_debug("dns_name_apply_idna: \"%s\" → %d/\"%s\" (expected %d/\"%s\")",
                  s, r, strnull(buf), expected, strnull(result));

        /* Different libidn2 versions are more and less accepting
         * of underscore-prefixed names. So let's list the lowest
         * expected return value. */
        assert_se(r >= expected);
        if (expected == 1)
                assert_se(dns_name_equal(buf, result) == 1);
}

TEST(dns_name_apply_idna) {
        const int ret = HAVE_LIBIDN2 | HAVE_LIBIDN;

        /* IDNA2008 forbids names with hyphens in third and fourth positions
         * (https://tools.ietf.org/html/rfc5891#section-4.2.3.1).
         * IDNA2003 does not have this restriction
         * (https://tools.ietf.org/html/rfc3490#section-5).
         * This means that when using libidn we will transform and test more
         * labels. If registrars follow IDNA2008 we'll just be performing a
         * useless lookup.
         */
        const int ret2 = HAVE_LIBIDN;

        test_dns_name_apply_idna_one("", ret, "");
        test_dns_name_apply_idna_one("foo", ret, "foo");
        test_dns_name_apply_idna_one("foo.", ret, "foo");
        test_dns_name_apply_idna_one("foo.bar", ret, "foo.bar");
        test_dns_name_apply_idna_one("foo.bar.", ret, "foo.bar");
        test_dns_name_apply_idna_one("föö", ret, "xn--f-1gaa");
        test_dns_name_apply_idna_one("föö.", ret, "xn--f-1gaa");
        test_dns_name_apply_idna_one("föö.bär", ret, "xn--f-1gaa.xn--br-via");
        test_dns_name_apply_idna_one("föö.bär.", ret, "xn--f-1gaa.xn--br-via");
        test_dns_name_apply_idna_one("xn--f-1gaa.xn--br-via", ret, "xn--f-1gaa.xn--br-via");

        test_dns_name_apply_idna_one("_443._tcp.fedoraproject.org", ret2,
                                     "_443._tcp.fedoraproject.org");
        test_dns_name_apply_idna_one("_443", ret2, "_443");
        test_dns_name_apply_idna_one("gateway", ret, "gateway");
        test_dns_name_apply_idna_one("_gateway", ret2, "_gateway");

        test_dns_name_apply_idna_one("r3---sn-ab5l6ne7.googlevideo.com", ret2,
                                     ret2 ? "r3---sn-ab5l6ne7.googlevideo.com" : "");
}

TEST(dns_name_is_valid_or_address) {
        assert_se(dns_name_is_valid_or_address(NULL) == 0);
        assert_se(dns_name_is_valid_or_address("") == 0);
        assert_se(dns_name_is_valid_or_address("foobar") > 0);
        assert_se(dns_name_is_valid_or_address("foobar.com") > 0);
        assert_se(dns_name_is_valid_or_address("foobar..com") == 0);
        assert_se(dns_name_is_valid_or_address("foobar.com.") > 0);
        assert_se(dns_name_is_valid_or_address("127.0.0.1") > 0);
        assert_se(dns_name_is_valid_or_address("::") > 0);
        assert_se(dns_name_is_valid_or_address("::1") > 0);
}

TEST(dns_name_dot_suffixed) {
        assert_se(dns_name_dot_suffixed("") == 0);
        assert_se(dns_name_dot_suffixed(".") > 0);
        assert_se(dns_name_dot_suffixed("foo") == 0);
        assert_se(dns_name_dot_suffixed("foo.") > 0);
        assert_se(dns_name_dot_suffixed("foo\\..") > 0);
        assert_se(dns_name_dot_suffixed("foo\\.") == 0);
        assert_se(dns_name_dot_suffixed("foo.bar.") > 0);
        assert_se(dns_name_dot_suffixed("foo.bar\\.\\.\\..") > 0);
        assert_se(dns_name_dot_suffixed("foo.bar\\.\\.\\.\\.") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
