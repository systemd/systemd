/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <sys/param.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "ether-addr-util.h"
#include "hostname-setup.h"
#include "network-internal.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-route-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_deserialize_in_addr(void) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        _cleanup_free_ struct in6_addr *addresses6 = NULL;
        union in_addr_union a, b, c, d, e, f;
        int size;
        const char *addresses_string = "192.168.0.1 0:0:0:0:0:FFFF:204.152.189.116 192.168.0.2 ::1 192.168.0.3 1:0:0:0:0:0:0:8";

        assert_se(in_addr_from_string(AF_INET, "0:0:0:0:0:FFFF:204.152.189.116", &a) < 0);
        assert_se(in_addr_from_string(AF_INET6, "192.168.0.1", &d) < 0);

        assert_se(in_addr_from_string(AF_INET, "192.168.0.1", &a) >= 0);
        assert_se(in_addr_from_string(AF_INET, "192.168.0.2", &b) >= 0);
        assert_se(in_addr_from_string(AF_INET, "192.168.0.3", &c) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116", &d) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "::1", &e) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "1:0:0:0:0:0:0:8", &f) >= 0);

        assert_se((size = deserialize_in_addrs(&addresses, addresses_string)) >= 0);
        assert_se(size == 3);
        assert_se(in4_addr_equal(&a.in, &addresses[0]));
        assert_se(in4_addr_equal(&b.in, &addresses[1]));
        assert_se(in4_addr_equal(&c.in, &addresses[2]));

        assert_se((size = deserialize_in6_addrs(&addresses6, addresses_string)) >= 0);
        assert_se(size == 3);
        assert_se(in6_addr_equal(&d.in6, &addresses6[0]));
        assert_se(in6_addr_equal(&e.in6, &addresses6[1]));
        assert_se(in6_addr_equal(&f.in6, &addresses6[2]));
}

static void test_deserialize_dhcp_routes(void) {
        size_t size;

        {
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                assert_se(deserialize_dhcp_routes(&routes, &size, "") >= 0);
                assert_se(size == 0);
        }

        {
                /* no errors */
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                const char *routes_string = "192.168.0.0/16,192.168.0.1 10.1.2.0/24,10.1.2.1 0.0.0.0/0,10.0.1.1";

                assert_se(deserialize_dhcp_routes(&routes, &size, routes_string) >= 0);

                assert_se(size == 3);
                assert_se(routes[0].dst_addr.s_addr == inet_addr("192.168.0.0"));
                assert_se(routes[0].gw_addr.s_addr == inet_addr("192.168.0.1"));
                assert_se(routes[0].dst_prefixlen == 16);

                assert_se(routes[1].dst_addr.s_addr == inet_addr("10.1.2.0"));
                assert_se(routes[1].gw_addr.s_addr == inet_addr("10.1.2.1"));
                assert_se(routes[1].dst_prefixlen == 24);

                assert_se(routes[2].dst_addr.s_addr == inet_addr("0.0.0.0"));
                assert_se(routes[2].gw_addr.s_addr == inet_addr("10.0.1.1"));
                assert_se(routes[2].dst_prefixlen == 0);
        }

        {
                /* error in second word */
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                const char *routes_string = "192.168.0.0/16,192.168.0.1 10.1.2.0#24,10.1.2.1 0.0.0.0/0,10.0.1.1";

                assert_se(deserialize_dhcp_routes(&routes, &size, routes_string) >= 0);

                assert_se(size == 2);
                assert_se(routes[0].dst_addr.s_addr == inet_addr("192.168.0.0"));
                assert_se(routes[0].gw_addr.s_addr == inet_addr("192.168.0.1"));
                assert_se(routes[0].dst_prefixlen == 16);

                assert_se(routes[1].dst_addr.s_addr == inet_addr("0.0.0.0"));
                assert_se(routes[1].gw_addr.s_addr == inet_addr("10.0.1.1"));
                assert_se(routes[1].dst_prefixlen == 0);
        }

        {
                /* error in every word */
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                const char *routes_string = "192.168.0.0/55,192.168.0.1 10.1.2.0#24,10.1.2.1 0.0.0.0/0,10.0.1.X";

                assert_se(deserialize_dhcp_routes(&routes, &size, routes_string) >= 0);
                assert_se(size == 0);
        }
}

static void test_route_tables_one(Manager *manager, const char *name, uint32_t number) {
        _cleanup_free_ char *str = NULL, *expected = NULL, *num_str = NULL;
        uint32_t t;

        if (!STR_IN_SET(name, "default", "main", "local")) {
                assert_se(streq(hashmap_get(manager->route_table_names_by_number, UINT32_TO_PTR(number)), name));
                assert_se(PTR_TO_UINT32(hashmap_get(manager->route_table_numbers_by_name, name)) == number);
        }

        assert_se(asprintf(&expected, "%s(%" PRIu32 ")", name, number) >= 0);
        assert_se(manager_get_route_table_to_string(manager, number, /* append_num = */ true, &str) >= 0);
        assert_se(streq(str, expected));

        str = mfree(str);

        assert_se(manager_get_route_table_to_string(manager, number, /* append_num = */ false, &str) >= 0);
        assert_se(streq(str, name));

        assert_se(manager_get_route_table_from_string(manager, name, &t) >= 0);
        assert_se(t == number);

        assert_se(asprintf(&num_str, "%" PRIu32, number) >= 0);
        assert_se(manager_get_route_table_from_string(manager, num_str, &t) >= 0);
        assert_se(t == number);
}

static void test_route_tables(Manager *manager) {
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "hoge:123 foo:456 aaa:111", manager, manager) >= 0);
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "bbb:11111 ccc:22222", manager, manager) >= 0);
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "ddd:22222", manager, manager) >= 0);

        test_route_tables_one(manager, "hoge", 123);
        test_route_tables_one(manager, "foo", 456);
        test_route_tables_one(manager, "aaa", 111);
        test_route_tables_one(manager, "bbb", 11111);
        test_route_tables_one(manager, "ccc", 22222);

        assert_se(!hashmap_get(manager->route_table_numbers_by_name, "ddd"));

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);

        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "", manager, manager) >= 0);
        assert_se(!manager->route_table_names_by_number);
        assert_se(!manager->route_table_numbers_by_name);

        /* Invalid pairs */
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "main:123 default:333 local:999", manager, manager) >= 0);
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "xxx:253 yyy:254 local:255", manager, manager) >= 0);
        assert_se(config_parse_route_table_names("manager", "filename", 1, "section", 1, "RouteTable", 0, "1234:321 :567 hoge:foo aaa:-888", manager, manager) >= 0);
        assert_se(!manager->route_table_names_by_number);
        assert_se(!manager->route_table_numbers_by_name);

        test_route_tables_one(manager, "default", 253);
        test_route_tables_one(manager, "main", 254);
        test_route_tables_one(manager, "local", 255);
}

static int test_load_config(Manager *manager) {
        int r;
/*  TODO: should_reload, is false if the config dirs do not exist, so
 *        so we can't do this test here, move it to a test for paths_check_timestamps
 *        directly
 *
 *        assert_se(network_should_reload(manager) == true);
*/

        r = manager_load_config(manager);
        if (r == -EPERM)
                return r;
        assert_se(r >= 0);

        return 0;
}

static void test_dhcp_hostname_shorten_overlong(void) {
        int r;

        {
                /* simple hostname, no actions, no errors */
                _cleanup_free_ char *shortened = NULL;
                r = shorten_overlong("name1", &shortened);
                assert_se(r == 0);
                assert_se(streq("name1", shortened));
        }

        {
                /* simple fqdn, no actions, no errors */
                _cleanup_free_ char *shortened = NULL;
                r = shorten_overlong("name1.example.com", &shortened);
                assert_se(r == 0);
                assert_se(streq("name1.example.com", shortened));
        }

        {
                /* overlong fqdn, cut to first dot, no errors */
                _cleanup_free_ char *shortened = NULL;
                r = shorten_overlong("name1.test-dhcp-this-one-here-is-a-very-very-long-domain.example.com", &shortened);
                assert_se(r == 1);
                assert_se(streq("name1", shortened));
        }

        {
                /* overlong hostname, cut to HOST_MAX_LEN, no errors */
                _cleanup_free_ char *shortened = NULL;
                r = shorten_overlong("test-dhcp-this-one-here-is-a-very-very-long-hostname-without-domainname", &shortened);
                assert_se(r == 1);
                assert_se(streq("test-dhcp-this-one-here-is-a-very-very-long-hostname-without-dom", shortened));
        }

        {
                /* overlong fqdn, cut to first dot, empty result error */
                _cleanup_free_ char *shortened = NULL;
                r = shorten_overlong(".test-dhcp-this-one-here-is-a-very-very-long-hostname.example.com", &shortened);
                assert_se(r == -EDOM);
                assert_se(shortened == NULL);
        }
}

int main(void) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        test_deserialize_in_addr();
        test_deserialize_dhcp_routes();
        test_dhcp_hostname_shorten_overlong();

        assert_se(manager_new(&manager, /* test_mode = */ true) >= 0);
        assert_se(manager_setup(manager) >= 0);

        test_route_tables(manager);

        r = test_load_config(manager);
        if (r == -EPERM)
                log_debug("Cannot load configuration, ignoring.");
        else
                assert_se(r == 0);

        assert_se(manager_enumerate(manager) >= 0);
        return 0;
}
