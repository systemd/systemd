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

int main(int argc, char *argv[]) {
        test_socket_address_parse();
        test_socket_address_parse_netlink();
        test_socket_address_equal();
        test_socket_address_get_path();
}
