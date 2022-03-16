/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "net-condition.h"
#include "networkd-address.h"
#include "networkd-conf.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "strv.h"
#include "tests.h"

static void test_config_parse_duid_type_one(const char *rvalue, int ret, DUIDType expected, usec_t expected_time) {
        DUID actual = {};
        int r;

        r = config_parse_duid_type("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL);
        log_info_errno(r, "\"%s\" → %d (%m)", rvalue, actual.type);
        assert_se(r == ret);
        assert_se(expected == actual.type);
        if (expected == DUID_TYPE_LLT)
                assert_se(expected_time == actual.llt_time);
}

TEST(config_parse_duid_type) {
        test_config_parse_duid_type_one("", 0, 0, 0);
        test_config_parse_duid_type_one("link-layer-time", 0, DUID_TYPE_LLT, 0);
        test_config_parse_duid_type_one("link-layer-time:2000-01-01 00:00:00 UTC", 0, DUID_TYPE_LLT, (usec_t) 946684800000000);
        test_config_parse_duid_type_one("vendor", 0, DUID_TYPE_EN, 0);
        test_config_parse_duid_type_one("vendor:2000-01-01 00:00:00 UTC", 0, 0, 0);
        test_config_parse_duid_type_one("link-layer", 0, DUID_TYPE_LL, 0);
        test_config_parse_duid_type_one("link-layer:2000-01-01 00:00:00 UTC", 0, 0, 0);
        test_config_parse_duid_type_one("uuid", 0, DUID_TYPE_UUID, 0);
        test_config_parse_duid_type_one("uuid:2000-01-01 00:00:00 UTC", 0, 0, 0);
        test_config_parse_duid_type_one("foo", 0, 0, 0);
        test_config_parse_duid_type_one("foo:2000-01-01 00:00:00 UTC", 0, 0, 0);
}

static void test_config_parse_duid_rawdata_one(const char *rvalue, int ret, const DUID* expected) {
        DUID actual = {};
        int r;
        _cleanup_free_ char *d = NULL;

        r = config_parse_duid_rawdata("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL);
        d = hexmem(actual.raw_data, actual.raw_data_len);
        log_info_errno(r, "\"%s\" → \"%s\" (%m)",
                       rvalue, strnull(d));
        assert_se(r == ret);
        if (expected) {
                assert_se(actual.raw_data_len == expected->raw_data_len);
                assert_se(memcmp(actual.raw_data, expected->raw_data, expected->raw_data_len) == 0);
        }
}

static void test_config_parse_ether_addr_one(const char *rvalue, int ret, const struct ether_addr* expected) {
        struct ether_addr *actual = NULL;
        int r;

        r = config_parse_ether_addr("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL);
        assert_se(ret == r);
        if (expected) {
                assert_se(actual);
                assert_se(ether_addr_equal(expected, actual));
        } else
                assert_se(actual == NULL);

        free(actual);
}

static void test_config_parse_ether_addrs_one(const char *rvalue, const struct ether_addr* list, size_t n) {
        _cleanup_set_free_free_ Set *s = NULL;

        assert_se(config_parse_ether_addrs("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &s, NULL) == 0);
        assert_se(set_size(s) == n);

        for (size_t m = 0; m < n; m++) {
                _cleanup_free_ struct ether_addr *q = NULL;

                assert_se(q = set_remove(s, &list[m]));
        }

        assert_se(set_size(s) == 0);
}

#define BYTES_0_128 "0:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f:40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a:5b:5c:5d:5e:5f:60:61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f:80"

#define BYTES_1_128 {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x80}

TEST(config_parse_duid_rawdata) {
        test_config_parse_duid_rawdata_one("", 0, &(DUID){});
        test_config_parse_duid_rawdata_one("00:11:22:33:44:55:66:77", 0,
                                           &(DUID){0, 8, {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77}});
        test_config_parse_duid_rawdata_one("00:11:22:", 0,
                                           &(DUID){0, 3, {0x00,0x11,0x22}});
        test_config_parse_duid_rawdata_one("000:11:22", 0, &(DUID){}); /* error, output is all zeros */
        test_config_parse_duid_rawdata_one("00:111:22", 0, &(DUID){});
        test_config_parse_duid_rawdata_one("0:1:2:3:4:5:6:7", 0,
                                           &(DUID){0, 8, {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}});
        test_config_parse_duid_rawdata_one("11::", 0, &(DUID){0, 1, {0x11}});  /* FIXME: should this be an error? */
        test_config_parse_duid_rawdata_one("abcdef", 0, &(DUID){});
        test_config_parse_duid_rawdata_one(BYTES_0_128, 0, &(DUID){});
        test_config_parse_duid_rawdata_one(&BYTES_0_128[2], 0, &(DUID){0, 128, BYTES_1_128});
}

TEST(config_parse_ether_addr) {
        const struct ether_addr t[] = {
                { .ether_addr_octet = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } },
                { .ether_addr_octet = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } },
        };

        test_config_parse_ether_addr_one("", 0, NULL);
        test_config_parse_ether_addr_one("no:ta:ma:ca:dd:re", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:fx", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff", 0, &t[0]);
        test_config_parse_ether_addr_one(" aa:bb:cc:dd:ee:ff", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff \t\n", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff \t\nxxx", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc: dd:ee:ff", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:d d:ee:ff", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee", 0, NULL);
        test_config_parse_ether_addr_one("9:aa:bb:cc:dd:ee:ff", 0, NULL);
        test_config_parse_ether_addr_one("aa:bb:cc:dd:ee:ff:gg", 0, NULL);
        test_config_parse_ether_addr_one("aa:Bb:CC:dd:ee:ff", 0, &t[0]);
        test_config_parse_ether_addr_one("01:23:45:67:89:aB", 0, &t[1]);
        test_config_parse_ether_addr_one("1:23:45:67:89:aB", 0, &t[1]);
        test_config_parse_ether_addr_one("aa-bb-cc-dd-ee-ff", 0, &t[0]);
        test_config_parse_ether_addr_one("AA-BB-CC-DD-EE-FF", 0, &t[0]);
        test_config_parse_ether_addr_one("01-23-45-67-89-ab", 0, &t[1]);
        test_config_parse_ether_addr_one("aabb.ccdd.eeff", 0, &t[0]);
        test_config_parse_ether_addr_one("0123.4567.89ab", 0, &t[1]);
        test_config_parse_ether_addr_one("123.4567.89ab.", 0, NULL);
        test_config_parse_ether_addr_one("aabbcc.ddeeff", 0, NULL);
        test_config_parse_ether_addr_one("aabbccddeeff", 0, NULL);
        test_config_parse_ether_addr_one("aabbccddee:ff", 0, NULL);
        test_config_parse_ether_addr_one("012345.6789ab", 0, NULL);
        test_config_parse_ether_addr_one("123.4567.89ab", 0, &t[1]);

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

        assert_se(manager_new(&manager, /* test_mode = */ true) >= 0);
        assert_se(network = new0(Network, 1));
        network->n_ref = 1;
        network->manager = manager;
        assert_se(network->filename = strdup("hogehoge.network"));

        assert_se(config_parse_match_ifnames("network", "filename", 1, "section", 1, "Name", 0, "*", &network->match.ifname, network) == 0);
        assert_se(config_parse_address("network", "filename", 1, "section", 1, "Address", 0, rvalue, network, network) == 0);
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
        test_config_parse_address_one("1.2.3.4", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 8);
        test_config_parse_address_one("1.2.3.4/0", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 0);
        test_config_parse_address_one("1.2.3.4/1", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 1);
        test_config_parse_address_one("1.2.3.4/2", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 2);
        test_config_parse_address_one("1.2.3.4/32", AF_INET, 1, &(union in_addr_union) { .in = (struct in_addr) { .s_addr = htobe32(0x01020304) } }, 32);
        test_config_parse_address_one("1.2.3.4/33", AF_INET, 0, NULL, 0);
        test_config_parse_address_one("1.2.3.4/-1", AF_INET, 0, NULL, 0);

        test_config_parse_address_one("", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("/", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("/8", AF_INET6, 0, NULL, 0);
        test_config_parse_address_one("::1", AF_INET6, 1, &(union in_addr_union) { .in6 = IN6ADDR_LOOPBACK_INIT }, 0);
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

DEFINE_TEST_MAIN(LOG_INFO);
