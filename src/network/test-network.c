/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <sys/param.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "hostname-util.h"
#include "network-internal.h"
#include "networkd-manager.h"
#include "string-util.h"
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
        assert_se(in_addr_equal(AF_INET, &a, (union in_addr_union *) &addresses[0]));
        assert_se(in_addr_equal(AF_INET, &b, (union in_addr_union *) &addresses[1]));
        assert_se(in_addr_equal(AF_INET, &c, (union in_addr_union *) &addresses[2]));

        assert_se((size = deserialize_in6_addrs(&addresses6, addresses_string)) >= 0);
        assert_se(size == 3);
        assert_se(in_addr_equal(AF_INET6, &d, (union in_addr_union *) &addresses6[0]));
        assert_se(in_addr_equal(AF_INET6, &e, (union in_addr_union *) &addresses6[1]));
        assert_se(in_addr_equal(AF_INET6, &f, (union in_addr_union *) &addresses6[2]));
}

static void test_deserialize_dhcp_routes(void) {
        size_t size, allocated;

        {
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                assert_se(deserialize_dhcp_routes(&routes, &size, &allocated, "") >= 0);
                assert_se(size == 0);
        }

        {
                /* no errors */
                _cleanup_free_ struct sd_dhcp_route *routes = NULL;
                const char *routes_string = "192.168.0.0/16,192.168.0.1 10.1.2.0/24,10.1.2.1 0.0.0.0/0,10.0.1.1";

                assert_se(deserialize_dhcp_routes(&routes, &size, &allocated, routes_string) >= 0);

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

                assert_se(deserialize_dhcp_routes(&routes, &size, &allocated, routes_string) >= 0);

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

                assert_se(deserialize_dhcp_routes(&routes, &size, &allocated, routes_string) >= 0);
                assert_se(size == 0);
        }
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

        assert_se(manager_should_reload(manager) == false);

        return 0;
}

static void test_network_get(Manager *manager, sd_device *loopback) {
        Network *network;
        const struct ether_addr mac = ETHER_ADDR_NULL;

        /* let's assume that the test machine does not have a .network file
           that applies to the loopback device... */
        assert_se(network_get(manager, loopback, "lo", &mac, &network) == -ENOENT);
        assert_se(!network);
}

static void test_address_equality(void) {
        _cleanup_(address_freep) Address *a1 = NULL, *a2 = NULL;

        assert_se(address_new(&a1) >= 0);
        assert_se(address_new(&a2) >= 0);

        assert_se(address_equal(NULL, NULL));
        assert_se(!address_equal(a1, NULL));
        assert_se(!address_equal(NULL, a2));
        assert_se(address_equal(a1, a2));

        a1->family = AF_INET;
        assert_se(!address_equal(a1, a2));

        a2->family = AF_INET;
        assert_se(address_equal(a1, a2));

        assert_se(in_addr_from_string(AF_INET, "192.168.3.9", &a1->in_addr) >= 0);
        assert_se(!address_equal(a1, a2));
        assert_se(in_addr_from_string(AF_INET, "192.168.3.9", &a2->in_addr) >= 0);
        assert_se(address_equal(a1, a2));
        assert_se(in_addr_from_string(AF_INET, "192.168.3.10", &a1->in_addr_peer) >= 0);
        assert_se(address_equal(a1, a2));
        assert_se(in_addr_from_string(AF_INET, "192.168.3.11", &a2->in_addr_peer) >= 0);
        assert_se(address_equal(a1, a2));
        a1->prefixlen = 10;
        assert_se(!address_equal(a1, a2));
        a2->prefixlen = 10;
        assert_se(address_equal(a1, a2));

        a1->family = AF_INET6;
        assert_se(!address_equal(a1, a2));

        a2->family = AF_INET6;
        assert_se(in_addr_from_string(AF_INET6, "2001:4ca0:4f01::2", &a1->in_addr) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:4ca0:4f01::2", &a2->in_addr) >= 0);
        assert_se(address_equal(a1, a2));

        a2->prefixlen = 8;
        assert_se(address_equal(a1, a2));

        assert_se(in_addr_from_string(AF_INET6, "2001:4ca0:4f01::1", &a2->in_addr) >= 0);
        assert_se(!address_equal(a1, a2));
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
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        int ifindex, r;

        test_setup_logging(LOG_INFO);

        test_deserialize_in_addr();
        test_deserialize_dhcp_routes();
        test_address_equality();
        test_dhcp_hostname_shorten_overlong();

        assert_se(manager_new(&manager) >= 0);

        r = test_load_config(manager);
        if (r == -EPERM)
                return log_tests_skipped("Cannot load configuration");
        assert_se(r == 0);

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(loopback);
        assert_se(sd_device_get_ifindex(loopback, &ifindex) >= 0);
        assert_se(ifindex == 1);

        test_network_get(manager, loopback);

        assert_se(manager_rtnl_enumerate_links(manager) >= 0);
}
