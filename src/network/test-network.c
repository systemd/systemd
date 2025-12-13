/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "network-internal.h"
#include "networkd-manager.h"
#include "networkd-route-util.h"
#include "strv.h"
#include "tests.h"

TEST(deserialize_in_addr) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        _cleanup_free_ struct in6_addr *addresses6 = NULL;
        union in_addr_union a, b, c, d, e, f;
        static const char *addresses_string = "192.168.0.1 0:0:0:0:0:FFFF:204.152.189.116 192.168.0.2 ::1 192.168.0.3 1:0:0:0:0:0:0:8";

        ASSERT_ERROR(in_addr_from_string(AF_INET, "0:0:0:0:0:FFFF:204.152.189.116", &a), EINVAL);
        ASSERT_ERROR(in_addr_from_string(AF_INET6, "192.168.0.1", &d), EINVAL);

        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.1", &a));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.2", &b));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.168.0.3", &c));
        ASSERT_OK(in_addr_from_string(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116", &d));
        ASSERT_OK(in_addr_from_string(AF_INET6, "::1", &e));
        ASSERT_OK(in_addr_from_string(AF_INET6, "1:0:0:0:0:0:0:8", &f));

        ASSERT_OK_EQ(deserialize_in_addrs(&addresses, addresses_string), 3);
        ASSERT_NOT_NULL(addresses);
        ASSERT_TRUE(in4_addr_equal(&a.in, &addresses[0]));
        ASSERT_TRUE(in4_addr_equal(&b.in, &addresses[1]));
        ASSERT_TRUE(in4_addr_equal(&c.in, &addresses[2]));

        ASSERT_OK_EQ(deserialize_in6_addrs(&addresses6, addresses_string), 3);
        ASSERT_NOT_NULL(addresses6);
        ASSERT_TRUE(in6_addr_equal(&d.in6, &addresses6[0]));
        ASSERT_TRUE(in6_addr_equal(&e.in6, &addresses6[1]));
        ASSERT_TRUE(in6_addr_equal(&f.in6, &addresses6[2]));
}

TEST(deserialize_dhcp_routes) {
        _cleanup_free_ struct sd_dhcp_route *routes = NULL;
        size_t size;

        ASSERT_OK(deserialize_dhcp_routes(&routes, &size, ""));
        ASSERT_EQ(size, 0U);
        ASSERT_NULL(routes);

        ASSERT_OK(deserialize_dhcp_routes(&routes, &size, "192.168.0.0/16,192.168.0.1 10.1.2.0/24,10.1.2.1 0.0.0.0/0,10.0.1.1"));
        ASSERT_EQ(size, 3U);
        ASSERT_NOT_NULL(routes);

        ASSERT_EQ(routes[0].dst_addr.s_addr, inet_addr("192.168.0.0"));
        ASSERT_EQ(routes[0].gw_addr.s_addr, inet_addr("192.168.0.1"));
        ASSERT_EQ(routes[0].dst_prefixlen, 16U);

        ASSERT_EQ(routes[1].dst_addr.s_addr, inet_addr("10.1.2.0"));
        ASSERT_EQ(routes[1].gw_addr.s_addr, inet_addr("10.1.2.1"));
        ASSERT_EQ(routes[1].dst_prefixlen, 24U);

        ASSERT_EQ(routes[2].dst_addr.s_addr, inet_addr("0.0.0.0"));
        ASSERT_EQ(routes[2].gw_addr.s_addr, inet_addr("10.0.1.1"));
        ASSERT_EQ(routes[2].dst_prefixlen, 0U);

        routes = mfree(routes);

        ASSERT_OK(deserialize_dhcp_routes(&routes, &size, "192.168.0.0/16,192.168.0.1 10.1.2.0#24,10.1.2.1 0.0.0.0/0,10.0.1.1"));
        ASSERT_EQ(size, 2U);
        ASSERT_NOT_NULL(routes);

        ASSERT_EQ(routes[0].dst_addr.s_addr, inet_addr("192.168.0.0"));
        ASSERT_EQ(routes[0].gw_addr.s_addr, inet_addr("192.168.0.1"));
        ASSERT_EQ(routes[0].dst_prefixlen, 16U);

        ASSERT_EQ(routes[1].dst_addr.s_addr, inet_addr("0.0.0.0"));
        ASSERT_EQ(routes[1].gw_addr.s_addr, inet_addr("10.0.1.1"));
        ASSERT_EQ(routes[1].dst_prefixlen, 0U);

        routes = mfree(routes);

        ASSERT_OK(deserialize_dhcp_routes(&routes, &size, "192.168.0.0/55,192.168.0.1 10.1.2.0#24,10.1.2.1 0.0.0.0/0,10.0.1.X"));
        ASSERT_EQ(size, 0U);
        ASSERT_NULL(routes);
}

static void test_route_tables_one(Manager *manager, const char *name, uint32_t number) {
        _cleanup_free_ char *str = NULL, *expected = NULL, *num_str = NULL;
        uint32_t t;

        if (!STR_IN_SET(name, "default", "main", "local")) {
                ASSERT_STREQ(hashmap_get(manager->route_table_names_by_number, UINT32_TO_PTR(number)), name);
                ASSERT_EQ(PTR_TO_UINT32(hashmap_get(manager->route_table_numbers_by_name, name)), number);
        }

        ASSERT_OK(asprintf(&expected, "%s(%" PRIu32 ")", name, number));
        ASSERT_OK(manager_get_route_table_to_string(manager, number, /* append_num= */ true, &str));
        ASSERT_STREQ(str, expected);

        str = mfree(str);

        ASSERT_OK(manager_get_route_table_to_string(manager, number, /* append_num= */ false, &str));
        ASSERT_STREQ(str, name);

        ASSERT_OK(manager_get_route_table_from_string(manager, name, &t));
        ASSERT_EQ(t, number);

        ASSERT_OK(asprintf(&num_str, "%" PRIu32, number));
        ASSERT_OK(manager_get_route_table_from_string(manager, num_str, &t));
        ASSERT_EQ(t, number);
}

TEST(route_tables) {
        _cleanup_(manager_freep) Manager *manager = NULL;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(manager_setup(manager));

        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "hoge:123 foo:456 aaa:111", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "bbb:11111 ccc:22222", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "ddd:22222", manager, manager));

        test_route_tables_one(manager, "hoge", 123);
        test_route_tables_one(manager, "foo", 456);
        test_route_tables_one(manager, "aaa", 111);
        test_route_tables_one(manager, "bbb", 11111);
        test_route_tables_one(manager, "ccc", 22222);

        ASSERT_NULL(hashmap_get(manager->route_table_numbers_by_name, "ddd"));

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);

        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "", manager, manager));
        ASSERT_NULL(manager->route_table_names_by_number);
        ASSERT_NULL(manager->route_table_numbers_by_name);

        /* Invalid pairs */
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "main:123 default:333 local:999", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "xxx:253 yyy:254 local:255", manager, manager));
        ASSERT_OK(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "1234:321 :567 hoge:foo aaa:-888", manager, manager));
        ASSERT_NULL(manager->route_table_names_by_number);
        ASSERT_NULL(manager->route_table_numbers_by_name);

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);
}

TEST(manager_enumerate) {
        _cleanup_(manager_freep) Manager *manager = NULL;

        ASSERT_OK(manager_new(&manager, /* test_mode= */ true));
        ASSERT_OK(manager_setup(manager));

        /* TODO: should_reload, is false if the config dirs do not exist, so we can't do this test here, move
         * it to a test for paths_check_timestamps directly. */
        if (ASSERT_OK_OR(manager_load_config(manager), -EPERM) < 0)
                return (void) log_tests_skipped("Cannot load configuration files");

        ASSERT_OK(manager_enumerate(manager));
}

TEST(dhcp_hostname_shorten_overlong) {
        _cleanup_free_ char *s = NULL;

        /* simple hostname, no actions, no errors */
        ASSERT_OK_ZERO(shorten_overlong("name1", &s));
        ASSERT_STREQ(s, "name1");
        s = mfree(s);

        /* simple fqdn, no actions, no errors */
        ASSERT_OK_ZERO(shorten_overlong("name1.example.com", &s));
        ASSERT_STREQ(s, "name1.example.com");
        s = mfree(s);

        /* overlong fqdn, cut to first dot, no errors */
        ASSERT_OK_POSITIVE(shorten_overlong("name1.test-dhcp-this-one-here-is-a-very-very-long-domain.example.com", &s));
        ASSERT_STREQ(s, "name1");
        s = mfree(s);

        /* overlong hostname, cut to HOST_MAX_LEN, no errors */
        ASSERT_OK_POSITIVE(shorten_overlong("test-dhcp-this-one-here-is-a-very-very-long-hostname-without-domainname", &s));
        ASSERT_STREQ(s, "test-dhcp-this-one-here-is-a-very-very-long-hostname-without-dom");
        s = mfree(s);

        /* overlong fqdn, cut to first dot, empty result error */
        ASSERT_ERROR(shorten_overlong(".test-dhcp-this-one-here-is-a-very-very-long-hostname.example.com", &s), EDOM);
        ASSERT_NULL(s);
}

DEFINE_TEST_MAIN(LOG_INFO);
