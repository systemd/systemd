/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "hexdecoct.h"
#include "net-condition.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-route-nexthop.h"
#include "ordered-set.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

static void test_config_parse_duid_type_one(const char *rvalue, DUIDType expected, usec_t expected_time) {
        DUID actual = {};

        ASSERT_OK(config_parse_duid_type("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL));
        ASSERT_EQ(actual.type, expected);
        if (expected == DUID_TYPE_LLT)
                ASSERT_EQ(actual.llt_time, expected_time);
}

TEST(config_parse_duid_type) {
        test_config_parse_duid_type_one("", 0, 0);
        test_config_parse_duid_type_one("link-layer-time", DUID_TYPE_LLT, 0);
        test_config_parse_duid_type_one("link-layer-time:2000-01-01 00:00:00 UTC", DUID_TYPE_LLT, (usec_t) 946684800000000);
        test_config_parse_duid_type_one("vendor", DUID_TYPE_EN, 0);
        test_config_parse_duid_type_one("vendor:2000-01-01 00:00:00 UTC", 0, 0);
        test_config_parse_duid_type_one("link-layer", DUID_TYPE_LL, 0);
        test_config_parse_duid_type_one("link-layer:2000-01-01 00:00:00 UTC", 0, 0);
        test_config_parse_duid_type_one("uuid", DUID_TYPE_UUID, 0);
        test_config_parse_duid_type_one("uuid:2000-01-01 00:00:00 UTC", 0, 0);
        test_config_parse_duid_type_one("foo", 0, 0);
        test_config_parse_duid_type_one("foo:2000-01-01 00:00:00 UTC", 0, 0);
}

static void test_config_parse_duid_rawdata_one(const char *rvalue, const DUID* expected) {
        DUID actual = {};

        ASSERT_OK(config_parse_duid_rawdata("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL));
        if (expected) {
                _cleanup_free_ char *d = NULL, *e = NULL;
                d = hexmem(actual.raw_data, actual.raw_data_len);
                e = hexmem(expected->raw_data, expected->raw_data_len);
                ASSERT_STREQ(strna(d), strna(e));
        }
}

static void test_config_parse_ether_addr_one(const char *rvalue, const struct ether_addr* expected) {
        _cleanup_free_ struct ether_addr *actual = NULL;

        ASSERT_OK(config_parse_ether_addr("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL));
        if (expected) {
                ASSERT_NOT_NULL(actual);
                ASSERT_STREQ(ETHER_ADDR_TO_STR(actual), ETHER_ADDR_TO_STR(expected));
        } else
                ASSERT_NULL(actual);
}

static void test_config_parse_ether_addrs_one(const char *rvalue, const struct ether_addr* list, size_t n) {
        _cleanup_set_free_ Set *s = NULL;

        ASSERT_OK(config_parse_ether_addrs("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &s, NULL));
        ASSERT_EQ(set_size(s), n);

        for (size_t m = 0; m < n; m++) {
                _cleanup_free_ struct ether_addr *q = NULL;

                ASSERT_NOT_NULL((q = set_remove(s, &list[m])));
        }

        ASSERT_TRUE(set_isempty(s));
}

#define STR_OK                                                          \
        "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"              \
        "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:"              \
        "20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:"              \
        "30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f:"              \
        "40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f:"              \
        "50:51:52:53:54:55:56:57:58:59:5a:5b:5c:5d:5e:5f:"              \
        "60:61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:"              \
        "70:71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f"
#define STR_TOO_LONG                                                    \
        "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"              \
        "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:"              \
        "20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:"              \
        "30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f:"              \
        "40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f:"              \
        "50:51:52:53:54:55:56:57:58:59:5a:5b:5c:5d:5e:5f:"              \
        "60:61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:"              \
        "70:71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f:"              \
        "80"

#define BYTES_OK {                                                                       \
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, \
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f, \
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f, \
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f, \
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f, \
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f, \
        0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f, \
        0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f, \
}

TEST(config_parse_duid_rawdata) {
        test_config_parse_duid_rawdata_one("", &(DUID){});
        test_config_parse_duid_rawdata_one("00:11:22:33:44:55:66:77",
                                           &(DUID){0, 8, {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77}});
        test_config_parse_duid_rawdata_one("00:11:22:",
                                           &(DUID){0, 3, {0x00,0x11,0x22}});
        test_config_parse_duid_rawdata_one("000:11:22", &(DUID){}); /* error, output is all zeros */
        test_config_parse_duid_rawdata_one("00:111:22", &(DUID){});
        test_config_parse_duid_rawdata_one("0:1:2:3:4:5:6:7",
                                           &(DUID){0, 8, {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}});
        test_config_parse_duid_rawdata_one("11::", &(DUID){0, 1, {0x11}});  /* FIXME: should this be an error? */
        test_config_parse_duid_rawdata_one("abcdef", &(DUID){});
        test_config_parse_duid_rawdata_one(STR_TOO_LONG, &(DUID){});
        test_config_parse_duid_rawdata_one(STR_OK, &(DUID){0, 128, BYTES_OK});
}

TEST(config_parse_ether_addr) {
        const struct ether_addr t[] = {
                { .ether_addr_octet = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } },
                { .ether_addr_octet = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } },
        };

        test_config_parse_ether_addr_one("", NULL);
        test_config_parse_ether_addr_one("no:ta:ma:ca:dd:re", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:fx", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff", &t[0]);
        test_config_parse_ether_addr_one(" aa:bb:cc:dd:ee:ff", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff \t\n", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff \t\nxxx", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc: dd:ee:ff", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:d d:ee:ff", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee", NULL);
        test_config_parse_ether_addr_one("9:aa:bb:cc:dd:ee:ff", NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff:gg", NULL);
        test_config_parse_ether_addr_one("aa:Bb:CC:dd:ee:ff", &t[0]);
        test_config_parse_ether_addr_one("01:23:45:67:89:aB", &t[1]);
        test_config_parse_ether_addr_one("1:23:45:67:89:aB", &t[1]);
        test_config_parse_ether_addr_one("aa-bb-cc-dd-ee-ff", &t[0]);
        test_config_parse_ether_addr_one("AA-BB-CC-DD-EE-FF", &t[0]);
        test_config_parse_ether_addr_one("01-23-45-67-89-ab", &t[1]);
        test_config_parse_ether_addr_one("aabb.ccdd.eeff", &t[0]);
        test_config_parse_ether_addr_one("0123.4567.89ab", &t[1]);
        test_config_parse_ether_addr_one("123.4567.89ab.", NULL);
        test_config_parse_ether_addr_one("aabbcc.ddeeff", NULL);
        test_config_parse_ether_addr_one("aabbccddeeff", NULL);
        test_config_parse_ether_addr_one("aabbccddee:ff", NULL);
        test_config_parse_ether_addr_one("012345.6789ab", NULL);
        test_config_parse_ether_addr_one("123.4567.89ab", &t[1]);

        test_config_parse_ether_addrs_one("", t, 0);
        test_config_parse_ether_addrs_one("no:ta:ma:ca:dd:re", t, 0);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee:fx", t, 0);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee:ff", t, 1);
        test_config_parse_ether_addrs_one(" aa:bb:cc:dd:ee:ff", t, 1);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee:ff \t\n", t, 1);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee:ff \t\nxxx", t, 1);
        test_config_parse_ether_addrs_one("aa:bb:cc: dd:ee:ff", t, 0);
        test_config_parse_ether_addrs_one("aa:bb:cc:d d:ee:ff", t, 0);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee", t, 0);
        test_config_parse_ether_addrs_one("9:aa:bb:cc:dd:ee:ff", t, 0);
        test_config_parse_ether_addrs_one("aa:bb:cc:dd:ee:ff:gg", t, 0);
        test_config_parse_ether_addrs_one("aa:Bb:CC:dd:ee:ff", t, 1);
        test_config_parse_ether_addrs_one("01:23:45:67:89:aB", &t[1], 1);
        test_config_parse_ether_addrs_one("1:23:45:67:89:aB", &t[1], 1);
        test_config_parse_ether_addrs_one("aa-bb-cc-dd-ee-ff", t, 1);
        test_config_parse_ether_addrs_one("AA-BB-CC-DD-EE-FF", t, 1);
        test_config_parse_ether_addrs_one("01-23-45-67-89-ab", &t[1], 1);
        test_config_parse_ether_addrs_one("aabb.ccdd.eeff", t, 1);
        test_config_parse_ether_addrs_one("0123.4567.89ab", &t[1], 1);
        test_config_parse_ether_addrs_one("123.4567.89ab.", t, 0);
        test_config_parse_ether_addrs_one("aabbcc.ddeeff", t, 0);
        test_config_parse_ether_addrs_one("aabbccddeeff", t, 0);
        test_config_parse_ether_addrs_one("aabbccddee:ff", t, 0);
        test_config_parse_ether_addrs_one("012345.6789ab", t, 0);
        test_config_parse_ether_addrs_one("123.4567.89ab", &t[1], 1);

        test_config_parse_ether_addrs_one("123.4567.89ab aa:bb:cc:dd:ee:ff 01-23-45-67-89-ab aa:Bb:CC:dd:ee:ff", t, 2);
        test_config_parse_ether_addrs_one("123.4567.89ab aa:bb:cc:dd:ee:fx hogehoge 01-23-45-67-89-ab aaaa aa:Bb:CC:dd:ee:ff", t, 2);
}

static void test_config_parse_address_one(const char *rvalue, int family, unsigned n_addresses, const union in_addr_union *u, unsigned char prefixlen) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_(network_unrefp) Network *network = NULL;

        assert_se(manager_new(&manager, /* test_mode= */ true) >= 0);
        assert_se(network = new0(Network, 1));
        network->n_ref = 1;
        network->manager = manager;
        assert_se(network->filename = strdup("hogehoge.network"));

        assert_se(config_parse_match_ifnames("network", "filename", 1, "section", 1, "Name", 0, "*", &network->match.ifname, network) == 0);
        assert_se(config_parse_address_section("network", "filename", 1, "section", 1, "Address", ADDRESS_ADDRESS, rvalue, network, network) == 0);
        assert_se(ordered_hashmap_size(network->addresses_by_section) == 1);
        assert_se(network_verify(network) >= 0);
        assert_se(ordered_hashmap_size(network->addresses_by_section) == n_addresses);
        if (n_addresses > 0) {
                Address *a;

                assert_se(a = ordered_hashmap_first(network->addresses_by_section));
                assert_se(a->prefixlen == prefixlen);
                assert_se(a->family == family);
                assert_se(in_addr_equal(family, &a->in_addr, u));
                /* TODO: check Address.in_addr and Address.broadcast */
        }
}

TEST(config_parse_address) {
        test_config_parse_address_one("", AF_INET, 0, NULL, 0);
        test_config_parse_address_one("/", AF_INET, 0, NULL, 0);
        test_config_parse_address_one("/8", AF_INET, 0, NULL, 0);
        test_config_parse_address_one("1.2.3.4", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32);
        test_config_parse_address_one("1.2.3.4/0", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 0);
        test_config_parse_address_one("1.2.3.4/1", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 1);
        test_config_parse_address_one("1.2.3.4/2", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 2);
        test_config_parse_address_one("1.2.3.4/32", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32);
        test_config_parse_address_one("1.2.3.4/33", AF_INET, 0, NULL, 0);
        test_config_parse_address_one("1.2.3.4/-1", AF_INET, 0, NULL, 0);

        test_config_parse_address_one("", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("/", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("/8", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("::1", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128);
        test_config_parse_address_one("::1/0", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 0);
        test_config_parse_address_one("::1/1", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 1);
        test_config_parse_address_one("::1/2", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 2);
        test_config_parse_address_one("::1/32", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 32);
        test_config_parse_address_one("::1/33", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 33);
        test_config_parse_address_one("::1/64", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 64);
        test_config_parse_address_one("::1/128", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 128);
        test_config_parse_address_one("::1/129", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("::1/-1", AF_INET6, 0, NULL, 0);
}

TEST(config_parse_match_ifnames) {
        _cleanup_strv_free_ char **names = NULL;

        assert_se(config_parse_match_ifnames("network", "filename", 1, "section", 1, "Name", 0, "!hoge hogehoge foo", &names, NULL) == 0);
        assert_se(config_parse_match_ifnames("network", "filename", 1, "section", 1, "Name", 0, "!baz", &names, NULL) == 0);
        assert_se(config_parse_match_ifnames("network", "filename", 1, "section", 1, "Name", 0, "aaa bbb ccc", &names, NULL) == 0);

        assert_se(strv_equal(names, STRV_MAKE("!hoge", "!hogehoge", "!foo", "!baz", "aaa", "bbb", "ccc")));
}

TEST(config_parse_match_strv) {
        _cleanup_strv_free_ char **names = NULL;

        assert_se(config_parse_match_strv("network", "filename", 1, "section", 1, "Name", 0, "!hoge hogehoge foo", &names, NULL) == 0);
        assert_se(config_parse_match_strv("network", "filename", 1, "section", 1, "Name", 0, "!baz", &names, NULL) == 0);
        assert_se(config_parse_match_strv("network", "filename", 1, "section", 1, "Name", 0,
                                          "KEY=val \"KEY2=val with space\" \"KEY3=val with \\\"quotation\\\"\"", &names, NULL) == 0);

        assert_se(strv_equal(names,
                             STRV_MAKE("!hoge",
                                       "!hogehoge",
                                       "!foo",
                                       "!baz",
                                       "KEY=val",
                                       "KEY2=val with space",
                                       "KEY3=val with \\quotation\\")));
}

static int parse_mpr(const char *rvalue, OrderedSet **nexthops) {
        return config_parse_multipath_route(
                        "network", "filename", 1, "section", 1, "MultiPathRoute", 0, rvalue, nexthops, NULL);
}

static void test_config_parse_multipath_route_one(const char *rvalue, int expected_ret, size_t expected_size) {
        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;

        ASSERT_OK_EQ(parse_mpr(rvalue, &nexthops), expected_ret);
        ASSERT_EQ(ordered_set_size(nexthops), expected_size);
}

static void test_config_parse_multipath_route_verify(
                const char *rvalue,
                int expected_family,
                const char *expected_gw,
                const char *expected_ifname,
                int expected_ifindex,
                uint32_t expected_weight) {

        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;
        RouteNextHop *nh;

        ASSERT_OK_EQ(parse_mpr(rvalue, &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);

        ASSERT_NOT_NULL(nh = ordered_set_first(nexthops));
        ASSERT_EQ(nh->family, expected_family);

        if (expected_gw) {
                union in_addr_union gw;
                ASSERT_OK(in_addr_from_string(expected_family, expected_gw, &gw));
                ASSERT_EQ(memcmp(&nh->gw, &gw, FAMILY_ADDRESS_SIZE(expected_family)), 0);
        } else
                ASSERT_FALSE(in_addr_is_set(nh->family, &nh->gw));

        ASSERT_STREQ(nh->ifname, expected_ifname);

        ASSERT_EQ(nh->ifindex, expected_ifindex);
        ASSERT_EQ(nh->weight, expected_weight);
}

TEST(config_parse_multipath_route) {
        _cleanup_ordered_set_free_ OrderedSet *nexthops = NULL;

        /* Device only routes */
        test_config_parse_multipath_route_verify("@wg0", AF_UNSPEC, NULL, "wg0", 0, 0);
        test_config_parse_multipath_route_verify("@wg0 10", AF_UNSPEC, NULL, "wg0", 0, 9);
        test_config_parse_multipath_route_verify("@eth0 255", AF_UNSPEC, NULL, "eth0", 0, 254);
        test_config_parse_multipath_route_verify("@1 15", AF_UNSPEC, NULL, NULL, 1, 14);

        /* Gateway with device */
        test_config_parse_multipath_route_verify("10.0.0.1@eth0", AF_INET, "10.0.0.1", "eth0", 0, 0);
        test_config_parse_multipath_route_verify("10.0.0.1@eth0 20", AF_INET, "10.0.0.1", "eth0", 0, 19);
        test_config_parse_multipath_route_verify("2001:db8::1@wg0 15", AF_INET6, "2001:db8::1", "wg0", 0, 14);

        /* Gateway without device */
        test_config_parse_multipath_route_verify("192.168.1.1", AF_INET, "192.168.1.1", NULL, 0, 0);
        test_config_parse_multipath_route_verify("192.168.1.1 100", AF_INET, "192.168.1.1", NULL, 0, 99);
        test_config_parse_multipath_route_verify("fe80::1", AF_INET6, "fe80::1", NULL, 0, 0);

        /* Interface index instead of name */
        test_config_parse_multipath_route_verify("10.0.0.1@5", AF_INET, "10.0.0.1", NULL, 5, 0);
        test_config_parse_multipath_route_verify("@10", AF_UNSPEC, NULL, NULL, 10, 0);
        test_config_parse_multipath_route_verify("@10 50", AF_UNSPEC, NULL, NULL, 10, 49);

        /* Empty value clears nexthops */
        ASSERT_OK_EQ(parse_mpr("@wg0 15", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);
        ASSERT_OK_EQ(parse_mpr("", &nexthops), 1);
        ASSERT_NULL(nexthops);

        /* Make sure device-only/AF_UNSPEC routes do not collapse into a single entry. */

        /* Different interfaces, same weight */
        ASSERT_OK_EQ(parse_mpr("@wg0 15", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);
        ASSERT_OK_EQ(parse_mpr("@wg1 15", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 2u);
        /* Same interface, different weights */
        ASSERT_OK_EQ(parse_mpr("@eth0 10", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("@eth0 20", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 4u);
        /* Interface name vs interface index */
        ASSERT_OK_EQ(parse_mpr("@5 15", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 5u);
        /* Mixing device-only and gateway routes */
        ASSERT_OK_EQ(parse_mpr("10.0.0.1@eth0 20", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("192.168.1.1 30", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 7u);
        /* Large interface index */
        ASSERT_OK_EQ(parse_mpr("@999999 10", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 8u);
        /* IPv4 and IPv6 mixing */
        ASSERT_OK_EQ(parse_mpr("2001:db8::1@eth0 20", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 9u);
        /* Default weight handling */
        ASSERT_OK_EQ(parse_mpr("@wg2", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("@wg3", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 11u);

        nexthops = ordered_set_free(nexthops);

        /* Insertion order does not affect deduplication */
        _cleanup_ordered_set_free_ OrderedSet *nexthops2 = NULL;
        ASSERT_OK_EQ(parse_mpr("@wg0 10", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("@wg1 20", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("@wg1 20", &nexthops2), 1);
        ASSERT_OK_EQ(parse_mpr("@wg0 10", &nexthops2), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 2u);
        ASSERT_EQ(ordered_set_size(nexthops2), 2u);

        nexthops = ordered_set_free(nexthops);

        /* Duplicate routes should be detected and rejected with a warning. */

        /* Exact duplicates are rejected */
        ASSERT_OK_EQ(parse_mpr("@wg0 15", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);
        ASSERT_OK_EQ(parse_mpr("@wg0 15", &nexthops), 0);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);

        nexthops = ordered_set_free(nexthops);

        /* Default weight vs explicit weight=1 are treated as identical */
        ASSERT_OK_EQ(parse_mpr("@eth0", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);
        ASSERT_OK_EQ(parse_mpr("@eth0 1", &nexthops), 0);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);

        nexthops = ordered_set_free(nexthops);

        /* Weight=1 then default weight (reverse order), still detected as duplicate */
        ASSERT_OK_EQ(parse_mpr("@wg0 1", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);
        ASSERT_OK_EQ(parse_mpr("@wg0", &nexthops), 0);
        ASSERT_EQ(ordered_set_size(nexthops), 1u);

        nexthops = ordered_set_free(nexthops);

        /* Device-only vs gateway with device are semantically distinct, both accepted */
        ASSERT_OK_EQ(parse_mpr("@eth0 10", &nexthops), 1);
        ASSERT_OK_EQ(parse_mpr("10.0.0.1@eth0 10", &nexthops), 1);
        ASSERT_EQ(ordered_set_size(nexthops), 2u);

        /* Invalid input should be rejected */

        /* Invalid gateway addresses */
        test_config_parse_multipath_route_one("999.999.999.999", 0, 0);
        test_config_parse_multipath_route_one("not-an-ip", 0, 0);
        test_config_parse_multipath_route_one("10", 0, 0);

        /* Invalid weights */
        test_config_parse_multipath_route_one("@wg0 0", 0, 0);   /* Weight 0 */
        test_config_parse_multipath_route_one("@wg0 257", 0, 0); /* Weight > 256 */
        test_config_parse_multipath_route_one("@wg0 -1", 0, 0);  /* Negative */
        test_config_parse_multipath_route_one("@wg0 abc", 0, 0); /* Non-numeric */
}

DEFINE_TEST_MAIN(LOG_INFO);
