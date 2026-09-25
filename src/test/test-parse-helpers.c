/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>

#include "parse-helpers.h"
#include "set.h"
#include "tests.h"

static void test_valid_item(
                const char *str,
                int expected_af,
                int expected_ip_protocol,
                uint16_t expected_nr_ports,
                uint16_t expected_port_min) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) >= 0);
        assert_se(af == expected_af);
        assert_se(ip_protocol == expected_ip_protocol);
        assert_se(nr_ports == expected_nr_ports);
        assert_se(port_min == expected_port_min);

        log_info("%s: \"%s\" ok", __func__, str);
}

static void test_invalid_item(const char *str) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) == -EINVAL);

        log_info("%s: \"%s\" ok", __func__, str);
}

TEST(valid_items) {
        test_valid_item("any", AF_UNSPEC, 0, 0, 0);
        test_valid_item("0-65535", AF_UNSPEC, 0, 0, 0);
        test_valid_item("ipv4", AF_INET, 0, 0, 0);
        test_valid_item("ipv6", AF_INET6, 0, 0, 0);
        test_valid_item("ipv4:any", AF_INET, 0, 0, 0);
        test_valid_item("ipv6:any", AF_INET6, 0, 0, 0);
        test_valid_item("tcp", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("tcp:any", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp:any", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("0", AF_UNSPEC, 0, 1, 0);
        test_valid_item("6666", AF_UNSPEC, 0, 1, 6666);
        test_valid_item("6666-6667", AF_UNSPEC, 0, 2, 6666);
        test_valid_item("65535", AF_UNSPEC, 0, 1, 65535);
        test_valid_item("1-65535", AF_UNSPEC, 0, 65535, 1);
        test_valid_item("ipv4:tcp", AF_INET, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv4:udp", AF_INET, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv6:tcp", AF_INET6, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv6:udp", AF_INET6, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv4:6666", AF_INET, 0, 1, 6666);
        test_valid_item("ipv6:6666", AF_INET6, 0, 1, 6666);
        test_valid_item("tcp:6666", AF_UNSPEC, IPPROTO_TCP, 1, 6666);
        test_valid_item("udp:6666", AF_UNSPEC, IPPROTO_UDP, 1, 6666);
        test_valid_item("ipv4:tcp:6666", AF_INET, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:tcp:6666", AF_INET6, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:udp:6666-6667", AF_INET6, IPPROTO_UDP, 2, 6666);
        test_valid_item("ipv6:tcp:any", AF_INET6, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv6:tcp:0", AF_INET6, IPPROTO_TCP, 1, 0);
}

TEST(invalid_items) {
        test_invalid_item("");
        test_invalid_item(":");
        test_invalid_item("::");
        test_invalid_item("any:");
        test_invalid_item("meh");
        test_invalid_item("zupa:meh");
        test_invalid_item("zupa:meh:eh");
        test_invalid_item("ip");
        test_invalid_item("dccp");
        test_invalid_item("ipv6meh");
        test_invalid_item("ipv6::");
        test_invalid_item("ipv6:ipv6");
        test_invalid_item("ipv6:icmp");
        test_invalid_item("65536");
        test_invalid_item("ipv6:tcp:6666-6665");
        test_invalid_item("ipv6:tcp:6666-100000");
        test_invalid_item("ipv6::6666");
        test_invalid_item("ipv6:tcp:any:");
        test_invalid_item("ipv6:tcp:any:ipv6");
        test_invalid_item("ipv6:tcp:6666:zupa");
        test_invalid_item("ipv6:tcp:6666:any");
        test_invalid_item("ipv6:tcp:6666 zupa");
        test_invalid_item("ipv6:tcp:6666: zupa");
        test_invalid_item("ipv6:tcp:6666\n zupa");
}

static int test_path_simplify_and_warn_one(const char *p, const char *q, PathSimplifyWarnFlags f) {
        _cleanup_free_ char *s = ASSERT_PTR(strdup(p));
        int a, b;

        a = path_simplify_and_warn(s, f, /* unit= */ NULL, /* filename= */ NULL, /* line= */ 0, "Foobar=");
        assert(streq_ptr(s, q));

        free(s);
        s = ASSERT_PTR(strdup(p));

        b = path_simplify_and_warn(s, f|PATH_CHECK_FATAL, /* unit= */ NULL, /* filename= */ NULL, /* line= */ 0, "Foobar=");
        assert(streq_ptr(s, q));

        assert(a == b);

        return a;
}

TEST(path_simplify_and_warn) {

        assert_se(test_path_simplify_and_warn_one("", "", 0) == -EINVAL);
        assert_se(test_path_simplify_and_warn_one("/", "/", 0) == 0);
        assert_se(test_path_simplify_and_warn_one("/foo/../bar", "/foo/../bar", 0) == -EINVAL);
        assert_se(test_path_simplify_and_warn_one("/foo/./bar", "/foo/bar", 0) == 0);
        assert_se(test_path_simplify_and_warn_one("/proc/self///fd", "/proc/self/fd", 0) == 0);
        assert_se(test_path_simplify_and_warn_one("/proc/self///fd", "/proc/self/fd", PATH_CHECK_NON_API_VFS) == -EINVAL);
        assert_se(test_path_simplify_and_warn_one("aaaa", "aaaa", 0) == 0);
        assert_se(test_path_simplify_and_warn_one("aaaa", "aaaa", PATH_CHECK_ABSOLUTE) == -EINVAL);
        assert_se(test_path_simplify_and_warn_one("aaaa", "aaaa", PATH_CHECK_RELATIVE) == 0);
        assert_se(test_path_simplify_and_warn_one("/aaaa", "/aaaa", 0) == 0);
        assert_se(test_path_simplify_and_warn_one("/aaaa", "/aaaa", PATH_CHECK_ABSOLUTE) == 0);
        assert_se(test_path_simplify_and_warn_one("/aaaa", "/aaaa", PATH_CHECK_RELATIVE) == -EINVAL);
}

static void check_families(Set *s, const int *expected, size_t n_expected) {
        ASSERT_EQ(set_size(s), n_expected);
        for (size_t i = 0; i < n_expected; i++)
                ASSERT_TRUE(set_contains(s, INT_TO_PTR(expected[i])));
}

#define ASSERT_FAMILIES(s, ...)                                                                                 \
        check_families(s, (const int[]) { __VA_ARGS__ }, ELEMENTSOF(((const int[]) { __VA_ARGS__ })))

TEST(parse_address_families) {
        _cleanup_set_free_ Set *s = NULL;
        bool allowlist = false;

        /* The empty string undoes any previous configuration. */
        ASSERT_OK(parse_address_families("AF_UNIX", &s, &allowlist));
        ASSERT_NOT_NULL(s);
        ASSERT_OK(parse_address_families("", &s, &allowlist));
        ASSERT_NULL(s);
        ASSERT_FALSE(allowlist);

        /* "none" is an empty allow list, i.e. all address families are denied. */
        ASSERT_OK(parse_address_families("AF_UNIX", &s, &allowlist));
        ASSERT_OK(parse_address_families("none", &s, &allowlist));
        ASSERT_NULL(s);
        ASSERT_TRUE(allowlist);

        /* Space- and comma-separated lists, with or without the AF_ prefix, in any case. */
        ASSERT_OK(parse_address_families("AF_UNIX AF_INET", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_FAMILIES(s, AF_UNIX, AF_INET);
        s = set_free(s);

        ASSERT_OK(parse_address_families("unix,inet", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_FAMILIES(s, AF_UNIX, AF_INET);
        s = set_free(s);

        ASSERT_OK(parse_address_families("af_unix, Inet6,,PACKET ", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_FAMILIES(s, AF_UNIX, AF_INET6, AF_PACKET);
        s = set_free(s);

        /* A leading '~' turns the list into a deny list. */
        ASSERT_OK(parse_address_families("~AF_INET6", &s, &allowlist));
        ASSERT_FALSE(allowlist);
        ASSERT_FAMILIES(s, AF_INET6);

        /* Further assignments extend the existing deny list, or remove entries from it. */
        ASSERT_OK(parse_address_families("~packet,netlink", &s, &allowlist));
        ASSERT_FALSE(allowlist);
        ASSERT_FAMILIES(s, AF_INET6, AF_PACKET, AF_NETLINK);

        ASSERT_OK(parse_address_families("inet6 AF_NETLINK", &s, &allowlist));
        ASSERT_FALSE(allowlist);
        ASSERT_FAMILIES(s, AF_PACKET);
        s = set_free(s);

        /* Same for an allow list. */
        ASSERT_OK(parse_address_families("unix", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_OK(parse_address_families("inet,inet6", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_FAMILIES(s, AF_UNIX, AF_INET, AF_INET6);

        ASSERT_OK(parse_address_families("~inet6", &s, &allowlist));
        ASSERT_TRUE(allowlist);
        ASSERT_FAMILIES(s, AF_UNIX, AF_INET);

        /* Unknown names are rejected, and quoting does not turn a list into one name. */
        ASSERT_ERROR(parse_address_families("AF_HUDDLDUDDL", &s, &allowlist), EINVAL);
        ASSERT_ERROR(parse_address_families("unix huddlduddl", &s, &allowlist), EINVAL);
        ASSERT_ERROR(parse_address_families("~unix,huddlduddl", &s, &allowlist), EINVAL);
        ASSERT_ERROR(parse_address_families("\"AF_UNIX AF_INET\"", &s, &allowlist), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
