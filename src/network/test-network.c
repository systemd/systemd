/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "networkd.h"
#include "network-internal.h"
#include "dhcp-lease-internal.h"

static void test_deserialize_in_addr(void) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        _cleanup_free_ struct in6_addr *addresses6 = NULL;
        struct in_addr  a, b, c;
        struct in6_addr d, e, f;
        int size;
        const char *addresses_string = "192.168.0.1 0:0:0:0:0:FFFF:204.152.189.116 192.168.0.2 ::1 192.168.0.3 1:0:0:0:0:0:0:8";

        assert_se(inet_pton(AF_INET, "0:0:0:0:0:FFFF:204.152.189.116", &a) == 0);
        assert_se(inet_pton(AF_INET6, "192.168.0.1", &d) == 0);

        assert_se(inet_pton(AF_INET, "192.168.0.1", &a) == 1);
        assert_se(inet_pton(AF_INET, "192.168.0.2", &b) == 1);
        assert_se(inet_pton(AF_INET, "192.168.0.3", &c) == 1);
        assert_se(inet_pton(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116", &d) == 1);
        assert_se(inet_pton(AF_INET6, "::1", &e) == 1);
        assert_se(inet_pton(AF_INET6, "1:0:0:0:0:0:0:8", &f) == 1);

        assert_se((size = deserialize_in_addrs(&addresses, addresses_string)) >= 0);
        assert_se(size == 3);
        assert_se(!memcmp(&a, &addresses[0], sizeof(struct in_addr)));
        assert_se(!memcmp(&b, &addresses[1], sizeof(struct in_addr)));
        assert_se(!memcmp(&c, &addresses[2], sizeof(struct in_addr)));

        assert_se((size = deserialize_in6_addrs(&addresses6, addresses_string)) >= 0);
        assert_se(size == 3);
        assert_se(!memcmp(&d, &addresses6[0], sizeof(struct in6_addr)));
        assert_se(!memcmp(&e, &addresses6[1], sizeof(struct in6_addr)));
        assert_se(!memcmp(&f, &addresses6[2], sizeof(struct in6_addr)));
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

static void test_network_get(Manager *manager, struct udev_device *loopback) {
        Network *network;
        const struct ether_addr mac = {};

        /* let's assume that the test machine does not have a .network file
           that applies to the loopback device... */
        assert_se(network_get(manager, loopback, "lo", &mac, &network) == -ENOENT);
        assert_se(!network);
}

static void test_address_equality(void) {
        _cleanup_address_free_ Address *a1 = NULL, *a2 = NULL;

        assert_se(address_new_dynamic(&a1) >= 0);
        assert_se(address_new_dynamic(&a2) >= 0);

        assert_se(address_equal(NULL, NULL));
        assert_se(!address_equal(a1, NULL));
        assert_se(!address_equal(NULL, a2));
        assert_se(address_equal(a1, a2));

        a1->family = AF_INET;
        assert_se(!address_equal(a1, a2));

        a2->family = AF_INET;
        assert_se(address_equal(a1, a2));

        assert_se(inet_pton(AF_INET, "192.168.3.9", &a1->in_addr.in));
        assert_se(address_equal(a1, a2));
        assert_se(inet_pton(AF_INET, "192.168.3.9", &a2->in_addr.in));
        assert_se(address_equal(a1, a2));
        a1->prefixlen = 10;
        assert_se(!address_equal(a1, a2));
        a2->prefixlen = 10;
        assert_se(address_equal(a1, a2));

        assert_se(inet_pton(AF_INET, "192.168.3.10", &a2->in_addr.in));
        assert_se(address_equal(a1, a2));

        a1->family = AF_INET6;
        assert_se(!address_equal(a1, a2));

        a2->family = AF_INET6;
        assert_se(inet_pton(AF_INET6, "2001:4ca0:4f01::2", &a1->in_addr.in6));
        assert_se(inet_pton(AF_INET6, "2001:4ca0:4f01::2", &a2->in_addr.in6));
        assert_se(address_equal(a1, a2));

        a2->prefixlen = 8;
        assert_se(address_equal(a1, a2));

        assert_se(inet_pton(AF_INET6, "2001:4ca0:4f01::1", &a2->in_addr.in6));
        assert_se(!address_equal(a1, a2));
}

int main(void) {
        _cleanup_manager_free_ Manager *manager = NULL;
        struct udev *udev;
        struct udev_device *loopback;
        int r;

        test_deserialize_in_addr();
        test_deserialize_dhcp_routes();
        test_address_equality();

        assert_se(manager_new(&manager) >= 0);

        r = test_load_config(manager);
        if (r == -EPERM)
                return EXIT_TEST_SKIP;

        udev = udev_new();
        assert_se(udev);

        loopback = udev_device_new_from_syspath(udev, "/sys/class/net/lo");
        assert_se(loopback);
        assert_se(udev_device_get_ifindex(loopback) == 1);

        test_network_get(manager, loopback);

        assert_se(manager_rtnl_enumerate_links(manager) >= 0);

        udev_device_unref(loopback);
        udev_unref(udev);
}
