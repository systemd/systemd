/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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

#include "socket-util.h"
#include "util.h"
#include "macro.h"
#include "log.h"

static void test_socket_address_parse(void) {
        SocketAddress a;

        assert_se(socket_address_parse(&a, "junk") < 0);
        assert_se(socket_address_parse(&a, "192.168.1.1") < 0);
        assert_se(socket_address_parse(&a, ".168.1.1") < 0);
        assert_se(socket_address_parse(&a, "989.168.1.1") < 0);
        assert_se(socket_address_parse(&a, "192.168.1.1:65536") < 0);
        assert_se(socket_address_parse(&a, "192.168.1.1:0") < 0);
        assert_se(socket_address_parse(&a, "0") < 0);
        assert_se(socket_address_parse(&a, "65536") < 0);

        assert_se(socket_address_parse(&a, "65535") >= 0);

        if (socket_ipv6_is_supported()) {
                assert_se(socket_address_parse(&a, "[::1]") < 0);
                assert_se(socket_address_parse(&a, "[::1]8888") < 0);
                assert_se(socket_address_parse(&a, "::1") < 0);
                assert_se(socket_address_parse(&a, "[::1]:0") < 0);
                assert_se(socket_address_parse(&a, "[::1]:65536") < 0);
                assert_se(socket_address_parse(&a, "[a:b:1]:8888") < 0);

                assert_se(socket_address_parse(&a, "8888") >= 0);
                assert_se(a.sockaddr.sa.sa_family == AF_INET6);

                assert_se(socket_address_parse(&a, "[2001:0db8:0000:85a3:0000:0000:ac1f:8001]:8888") >= 0);
                assert_se(a.sockaddr.sa.sa_family == AF_INET6);

                assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
                assert_se(a.sockaddr.sa.sa_family == AF_INET6);
        } else {
                assert_se(socket_address_parse(&a, "[::1]:8888") < 0);

                assert_se(socket_address_parse(&a, "8888") >= 0);
                assert_se(a.sockaddr.sa.sa_family == AF_INET);
        }

        assert_se(socket_address_parse(&a, "192.168.1.254:8888") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_INET);

        assert_se(socket_address_parse(&a, "/foo/bar") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_UNIX);

        assert_se(socket_address_parse(&a, "@abstract") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_UNIX);
}

static void test_socket_address_parse_netlink(void) {
        SocketAddress a;

        assert_se(socket_address_parse_netlink(&a, "junk") < 0);
        assert_se(socket_address_parse_netlink(&a, "") < 0);

        assert_se(socket_address_parse_netlink(&a, "route") >= 0);
        assert_se(socket_address_parse_netlink(&a, "route 10") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_NETLINK);
        assert_se(a.protocol == NETLINK_ROUTE);
}

static void test_socket_address_equal(void) {
        SocketAddress a;
        SocketAddress b;

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.168.1.1:888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.16.1.1:8888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "8888") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "/foo/bar/") >= 0);
        assert_se(!socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_parse(&b, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "/foo/bar") >= 0);
        assert_se(socket_address_parse(&b, "/foo/bar") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
        assert_se(socket_address_parse(&b, "[::1]:8888") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse(&a, "@abstract") >= 0);
        assert_se(socket_address_parse(&b, "@abstract") >= 0);
        assert_se(socket_address_equal(&a, &b));

        assert_se(socket_address_parse_netlink(&a, "firewall") >= 0);
        assert_se(socket_address_parse_netlink(&b, "firewall") >= 0);
        assert_se(socket_address_equal(&a, &b));
}

static void test_socket_address_get_path(void) {
        SocketAddress a;

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "@abstract") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
        assert_se(!socket_address_get_path(&a));

        assert_se(socket_address_parse(&a, "/foo/bar") >= 0);
        assert_se(streq(socket_address_get_path(&a), "/foo/bar"));
}

static void test_in_addr_prefix_intersect_one(unsigned f, const char *a, unsigned apl, const char *b, unsigned bpl, int result) {
        union in_addr_union ua, ub;

        assert_se(in_addr_from_string(f, a, &ua) >= 0);
        assert_se(in_addr_from_string(f, b, &ub) >= 0);

        assert_se(in_addr_prefix_intersect(f, &ua, apl, &ub, bpl) == result);
}

static void test_in_addr_prefix_intersect(void) {

        test_in_addr_prefix_intersect_one(AF_INET, "255.255.255.255", 32, "255.255.255.254", 32, 0);
        test_in_addr_prefix_intersect_one(AF_INET, "255.255.255.255", 0, "255.255.255.255", 32, 1);
        test_in_addr_prefix_intersect_one(AF_INET, "0.0.0.0", 0, "47.11.8.15", 32, 1);

        test_in_addr_prefix_intersect_one(AF_INET, "1.1.1.1", 24, "1.1.1.1", 24, 1);
        test_in_addr_prefix_intersect_one(AF_INET, "2.2.2.2", 24, "1.1.1.1", 24, 0);

        test_in_addr_prefix_intersect_one(AF_INET, "1.1.1.1", 24, "1.1.1.127", 25, 1);
        test_in_addr_prefix_intersect_one(AF_INET, "1.1.1.1", 24, "1.1.1.127", 26, 1);
        test_in_addr_prefix_intersect_one(AF_INET, "1.1.1.1", 25, "1.1.1.127", 25, 1);
        test_in_addr_prefix_intersect_one(AF_INET, "1.1.1.1", 25, "1.1.1.255", 25, 0);

        test_in_addr_prefix_intersect_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 128, 0);
        test_in_addr_prefix_intersect_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, 1);
        test_in_addr_prefix_intersect_one(AF_INET6, "::", 0, "beef:beef:beef:beef:beef:beef:beef:beef", 128, 1);

        test_in_addr_prefix_intersect_one(AF_INET6, "1::2", 64, "1::2", 64, 1);
        test_in_addr_prefix_intersect_one(AF_INET6, "2::2", 64, "1::2", 64, 0);

        test_in_addr_prefix_intersect_one(AF_INET6, "1::1", 120, "1::007f", 121, 1);
        test_in_addr_prefix_intersect_one(AF_INET6, "1::1", 120, "1::007f", 122, 1);
        test_in_addr_prefix_intersect_one(AF_INET6, "1::1", 121, "1::007f", 121, 1);
        test_in_addr_prefix_intersect_one(AF_INET6, "1::1", 121, "1::00ff", 121, 0);
}

static void test_in_addr_prefix_next_one(unsigned f, const char *before, unsigned pl, const char *after) {
        union in_addr_union ubefore, uafter, t;

        assert_se(in_addr_from_string(f, before, &ubefore) >= 0);

        t = ubefore;
        assert_se((in_addr_prefix_next(f, &t, pl) > 0) == !!after);

        if (after) {
                assert_se(in_addr_from_string(f, after, &uafter) >= 0);
                assert_se(in_addr_equal(f, &t, &uafter) > 0);
        }
}

static void test_in_addr_prefix_next(void) {

        test_in_addr_prefix_next_one(AF_INET, "192.168.0.0", 24, "192.168.1.0");
        test_in_addr_prefix_next_one(AF_INET, "192.168.0.0", 16, "192.169.0.0");
        test_in_addr_prefix_next_one(AF_INET, "192.168.0.0", 20, "192.168.16.0");

        test_in_addr_prefix_next_one(AF_INET, "0.0.0.0", 32, "0.0.0.1");
        test_in_addr_prefix_next_one(AF_INET, "255.255.255.255", 32, NULL);
        test_in_addr_prefix_next_one(AF_INET, "255.255.255.0", 24, NULL);

        test_in_addr_prefix_next_one(AF_INET6, "4400::", 128, "4400::0001");
        test_in_addr_prefix_next_one(AF_INET6, "4400::", 120, "4400::0100");
        test_in_addr_prefix_next_one(AF_INET6, "4400::", 127, "4400::0002");
        test_in_addr_prefix_next_one(AF_INET6, "4400::", 8, "4500::");
        test_in_addr_prefix_next_one(AF_INET6, "4400::", 7, "4600::");

        test_in_addr_prefix_next_one(AF_INET6, "::", 128, "::1");

        test_in_addr_prefix_next_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, NULL);
        test_in_addr_prefix_next_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", 120, NULL);

}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);

        test_socket_address_parse();
        test_socket_address_parse_netlink();
        test_socket_address_equal();
        test_socket_address_get_path();

        test_in_addr_prefix_intersect();
        test_in_addr_prefix_next();

        return 0;
}
