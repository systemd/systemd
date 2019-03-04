/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fnmatch.h>
#include <netinet/in.h>

#include "log.h"
#include "strv.h"
#include "in-addr-util.h"

static void test_in_addr_prefix_from_string_one(
                const char *p,
                int family,
                int ret,
                const union in_addr_union *u,
                unsigned char prefixlen,
                int ret_refuse,
                unsigned char prefixlen_refuse,
                int ret_legacy,
                unsigned char prefixlen_legacy) {

        union in_addr_union q;
        unsigned char l;
        int f, r;

        r = in_addr_prefix_from_string(p, family, &q, &l);
        assert_se(r == ret);

        if (r < 0)
                return;

        assert_se(in_addr_equal(family, &q, u));
        assert_se(l == prefixlen);

        r = in_addr_prefix_from_string_auto(p, &f, &q, &l);
        assert_se(r >= 0);

        assert_se(f == family);
        assert_se(in_addr_equal(family, &q, u));
        assert_se(l == prefixlen);

        r = in_addr_prefix_from_string_auto_internal(p, PREFIXLEN_REFUSE, &f, &q, &l);
        assert_se(r == ret_refuse);

        if (r >= 0) {
                assert_se(f == family);
                assert_se(in_addr_equal(family, &q, u));
                assert_se(l == prefixlen_refuse);
        }

        r = in_addr_prefix_from_string_auto_internal(p, PREFIXLEN_LEGACY, &f, &q, &l);
        assert_se(r == ret_legacy);

        if (r >= 0) {
                assert_se(f == family);
                assert_se(in_addr_equal(family, &q, u));
                assert_se(l == prefixlen_legacy);
        }
}

static void test_in_addr_prefix_from_string(void) {
        test_in_addr_prefix_from_string_one("", AF_INET, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("/", AF_INET, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("/8", AF_INET, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("1.2.3.4", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32, -ENOANO, 0, 0, 8);
        test_in_addr_prefix_from_string_one("1.2.3.4/0", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 0, 0, 0, 0, 0);
        test_in_addr_prefix_from_string_one("1.2.3.4/1", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 1, 0, 1, 0, 1);
        test_in_addr_prefix_from_string_one("1.2.3.4/2", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 2, 0, 2, 0, 2);
        test_in_addr_prefix_from_string_one("1.2.3.4/32", AF_INET, 0, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32, 0, 32, 0, 32);
        test_in_addr_prefix_from_string_one("1.2.3.4/33", AF_INET, -ERANGE, NULL, 0, -ERANGE, 0, -ERANGE, 0);
        test_in_addr_prefix_from_string_one("1.2.3.4/-1", AF_INET, -ERANGE, NULL, 0, -ERANGE, 0, -ERANGE, 0);
        test_in_addr_prefix_from_string_one("::1", AF_INET, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);

        test_in_addr_prefix_from_string_one("", AF_INET6, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("/", AF_INET6, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("/8", AF_INET6, -EINVAL, NULL, 0, -EINVAL, 0, -EINVAL, 0);
        test_in_addr_prefix_from_string_one("::1", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128, -ENOANO, 0, 0, 0);
        test_in_addr_prefix_from_string_one("::1/0", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 0, 0, 0, 0, 0);
        test_in_addr_prefix_from_string_one("::1/1", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 1, 0, 1, 0, 1);
        test_in_addr_prefix_from_string_one("::1/2", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 2, 0, 2, 0, 2);
        test_in_addr_prefix_from_string_one("::1/32", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 32, 0, 32, 0, 32);
        test_in_addr_prefix_from_string_one("::1/33", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 33, 0, 33, 0, 33);
        test_in_addr_prefix_from_string_one("::1/64", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 64, 0, 64, 0, 64);
        test_in_addr_prefix_from_string_one("::1/128", AF_INET6, 0, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128, 0, 128, 0, 128);
        test_in_addr_prefix_from_string_one("::1/129", AF_INET6, -ERANGE, NULL, 0, -ERANGE, 0, -ERANGE, 0);
        test_in_addr_prefix_from_string_one("::1/-1", AF_INET6, -ERANGE, NULL, 0, -ERANGE, 0, -ERANGE, 0);
}

static void test_in_addr_prefix_to_string_valid(int family, const char *p) {
        _cleanup_free_ char *str = NULL;
        union in_addr_union u;
        unsigned char l;

        log_info("/* %s */", p);

        assert_se(in_addr_prefix_from_string(p, family, &u, &l) >= 0);
        assert_se(in_addr_prefix_to_string(family, &u, l, &str) >= 0);
        assert_se(streq(str, p));
}

static void test_in_addr_prefix_to_string_unoptimized(int family, const char *p) {
        _cleanup_free_ char *str1 = NULL, *str2 = NULL;
        union in_addr_union u1, u2;
        unsigned char len1, len2;

        log_info("/* %s */", p);

        assert_se(in_addr_prefix_from_string(p, family, &u1, &len1) >= 0);
        assert_se(in_addr_prefix_to_string(family, &u1, len1, &str1) >= 0);
        assert_se(in_addr_prefix_from_string(str1, family, &u2, &len2) >= 0);
        assert_se(in_addr_prefix_to_string(family, &u2, len2, &str2) >= 0);

        assert_se(streq(str1, str2));
        assert_se(len1 == len2);
        assert_se(in_addr_equal(family, &u1, &u2) > 0);
}

static void test_in_addr_prefix_to_string(void) {
        test_in_addr_prefix_to_string_valid(AF_INET, "0.0.0.0/32");
        test_in_addr_prefix_to_string_valid(AF_INET, "1.2.3.4/0");
        test_in_addr_prefix_to_string_valid(AF_INET, "1.2.3.4/24");
        test_in_addr_prefix_to_string_valid(AF_INET, "1.2.3.4/32");
        test_in_addr_prefix_to_string_valid(AF_INET, "255.255.255.255/32");

        test_in_addr_prefix_to_string_valid(AF_INET6, "::1/128");
        test_in_addr_prefix_to_string_valid(AF_INET6, "fd00:abcd::1/64");
        test_in_addr_prefix_to_string_valid(AF_INET6, "fd00:abcd::1234:1/64");
        test_in_addr_prefix_to_string_valid(AF_INET6, "1111:2222:3333:4444:5555:6666:7777:8888/128");

        test_in_addr_prefix_to_string_unoptimized(AF_INET, "0.0.0.0");
        test_in_addr_prefix_to_string_unoptimized(AF_INET, "192.168.0.1");

        test_in_addr_prefix_to_string_unoptimized(AF_INET6, "fd00:0000:0000:0000:0000:0000:0000:0001/64");
        test_in_addr_prefix_to_string_unoptimized(AF_INET6, "fd00:1111::0000:2222:3333:4444:0001/64");
}

static void test_in_addr_random_prefix(void) {
        _cleanup_free_ char *str = NULL;
        union in_addr_union a;

        assert_se(in_addr_from_string(AF_INET, "192.168.10.1", &a) >= 0);

        assert_se(in_addr_random_prefix(AF_INET, &a, 31, 32) >= 0);
        assert_se(in_addr_to_string(AF_INET, &a, &str) >= 0);
        assert_se(STR_IN_SET(str, "192.168.10.0", "192.168.10.1"));
        str = mfree(str);

        assert_se(in_addr_random_prefix(AF_INET, &a, 24, 26) >= 0);
        assert_se(in_addr_to_string(AF_INET, &a, &str) >= 0);
        assert_se(startswith(str, "192.168.10."));
        str = mfree(str);

        assert_se(in_addr_random_prefix(AF_INET, &a, 16, 24) >= 0);
        assert_se(in_addr_to_string(AF_INET, &a, &str) >= 0);
        assert_se(fnmatch("192.168.[0-9]*.0", str, 0) == 0);
        str = mfree(str);

        assert_se(in_addr_random_prefix(AF_INET, &a, 8, 24) >= 0);
        assert_se(in_addr_to_string(AF_INET, &a, &str) >= 0);
        assert_se(fnmatch("192.[0-9]*.[0-9]*.0", str, 0) == 0);
        str = mfree(str);

        assert_se(in_addr_random_prefix(AF_INET, &a, 8, 16) >= 0);
        assert_se(in_addr_to_string(AF_INET, &a, &str) >= 0);
        assert_se(fnmatch("192.[0-9]*.0.0", str, 0) == 0);
        str = mfree(str);

        assert_se(in_addr_from_string(AF_INET6, "fd00::1", &a) >= 0);

        assert_se(in_addr_random_prefix(AF_INET6, &a, 16, 64) >= 0);
        assert_se(in_addr_to_string(AF_INET6, &a, &str) >= 0);
        assert_se(startswith(str, "fd00:"));
        str = mfree(str);

        assert_se(in_addr_random_prefix(AF_INET6, &a, 8, 16) >= 0);
        assert_se(in_addr_to_string(AF_INET6, &a, &str) >= 0);
        assert_se(fnmatch("fd??::", str, 0) == 0);
        str = mfree(str);
}

int main(int argc, char *argv[]) {
        test_in_addr_prefix_from_string();
        test_in_addr_random_prefix();
        test_in_addr_prefix_to_string();

        return 0;
}
