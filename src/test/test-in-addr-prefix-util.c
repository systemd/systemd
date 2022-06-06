/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "in-addr-prefix-util.h"
#include "tests.h"

static void test_in_addr_prefix_to_string_one(int f, const char *addr, unsigned prefixlen) {
        union in_addr_union ua;
        assert_se(in_addr_from_string(f, addr, &ua) >= 0);

        const char *r = IN_ADDR_PREFIX_TO_STRING(f, &ua, prefixlen);
        assert_se(r);
        printf("%s: %s/%u == %s\n", __func__, addr, prefixlen, r);
        assert_se(startswith(r, addr));

        assert_se(streq(r, IN_ADDR_PREFIX_TO_STRING(f, &ua, prefixlen)));
        assert_se(streq(IN_ADDR_PREFIX_TO_STRING(f, &ua, prefixlen), r));
}

TEST(in_addr_to_string_prefix) {
        test_in_addr_prefix_to_string_one(AF_INET, "192.168.0.1", 0);
        test_in_addr_prefix_to_string_one(AF_INET, "192.168.0.1", 1);
        test_in_addr_prefix_to_string_one(AF_INET, "192.168.0.1", 31);
        test_in_addr_prefix_to_string_one(AF_INET, "192.168.0.1", 32);
        test_in_addr_prefix_to_string_one(AF_INET, "192.168.0.1", 256);
        test_in_addr_prefix_to_string_one(AF_INET, "10.11.12.13", UINT_MAX);
        test_in_addr_prefix_to_string_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0);
        test_in_addr_prefix_to_string_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT_MAX);
        test_in_addr_prefix_to_string_one(AF_INET6, "::1", 11);
        test_in_addr_prefix_to_string_one(AF_INET6, "fe80::", 33);
}

static void test_config_parse_in_addr_prefixes_one(int family, const union in_addr_union *addr, uint8_t prefixlen, Set **prefixes) {
        const char *str = IN_ADDR_PREFIX_TO_STRING(family, addr, prefixlen);
        assert_se(str);

        assert_se(config_parse_in_addr_prefixes("unit", "filename", 1, "Service", 1, "IPAddressAllow", 0, str, prefixes, NULL) >= 0);

        assert_se(streq(str, IN_ADDR_PREFIX_TO_STRING(family, addr, prefixlen)));
        assert_se(streq(IN_ADDR_PREFIX_TO_STRING(family, addr, prefixlen), str));
}

static void test_config_parse_in_addr_prefixes(Set **ret) {
        _cleanup_set_free_ Set *prefixes = NULL;

        log_info("/* %s() */", __func__);

        for (uint32_t i = 0; i < 256; i++) {
                /* ipv4 link-local address */
                test_config_parse_in_addr_prefixes_one(AF_INET, &(union in_addr_union) {
                                .in.s_addr = htobe32((UINT32_C(169) << 24) |
                                                     (UINT32_C(254) << 16) |
                                                     (i << 8)),
                        }, 24, &prefixes);

                /* ipv6 multicast address */
                test_config_parse_in_addr_prefixes_one(AF_INET6, &(union in_addr_union) {
                                .in6.s6_addr[0] = 0xff,
                                .in6.s6_addr[1] = i,
                        }, 16, &prefixes);

                for (uint32_t j = 0; j < 256; j++) {
                        test_config_parse_in_addr_prefixes_one(AF_INET, &(union in_addr_union) {
                                        .in.s_addr = htobe32((UINT32_C(169) << 24) |
                                                             (UINT32_C(254) << 16) |
                                                             (i << 8) | j),
                                }, 32, &prefixes);

                        test_config_parse_in_addr_prefixes_one(AF_INET6, &(union in_addr_union) {
                                        .in6.s6_addr[0] = 0xff,
                                        .in6.s6_addr[1] = i,
                                        .in6.s6_addr[2] = j,
                                }, 24, &prefixes);
                }
        }

        *ret = TAKE_PTR(prefixes);
}

static void test_in_addr_prefixes_reduce(Set *prefixes) {
        log_info("/* %s() */", __func__);

        assert_se(set_size(prefixes) == 2 * 256 * 257);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(in_addr_prefixes_reduce(prefixes) >= 0);
        assert_se(set_size(prefixes) == 2 * 256);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(config_parse_in_addr_prefixes("unit", "filename", 1, "Service", 1, "IPAddressAllow", 0, "link-local", &prefixes, NULL) == 0);
        assert_se(set_size(prefixes) == 2 * 256 + 2);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(in_addr_prefixes_reduce(prefixes) >= 0);
        assert_se(set_size(prefixes) == 256 + 2);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(config_parse_in_addr_prefixes("unit", "filename", 1, "Service", 1, "IPAddressAllow", 0, "multicast", &prefixes, NULL) == 0);
        assert_se(set_size(prefixes) == 256 + 4);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(in_addr_prefixes_reduce(prefixes) >= 0);
        assert_se(set_size(prefixes) == 4);
        assert_se(!in_addr_prefixes_is_any(prefixes));

        assert_se(config_parse_in_addr_prefixes("unit", "filename", 1, "Service", 1, "IPAddressAllow", 0, "any", &prefixes, NULL) == 0);
        assert_se(set_size(prefixes) == 6);
        assert_se(in_addr_prefixes_is_any(prefixes));

        assert_se(in_addr_prefixes_reduce(prefixes) >= 0);
        assert_se(set_size(prefixes) == 2);
        assert_se(in_addr_prefixes_is_any(prefixes));
}

TEST(in_addr_prefixes) {
        _cleanup_set_free_ Set *prefixes = NULL;

        test_config_parse_in_addr_prefixes(&prefixes);
        test_in_addr_prefixes_reduce(prefixes);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
