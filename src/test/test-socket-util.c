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

#include "alloc-util.h"
#include "async.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "macro.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

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

        /* The checks below will pass even if ipv6 is disabled in
         * kernel. The underlying glibc's inet_pton() is just a string
         * parser and doesn't make any syscalls. */

        assert_se(socket_address_parse(&a, "[::1]") < 0);
        assert_se(socket_address_parse(&a, "[::1]8888") < 0);
        assert_se(socket_address_parse(&a, "::1") < 0);
        assert_se(socket_address_parse(&a, "[::1]:0") < 0);
        assert_se(socket_address_parse(&a, "[::1]:65536") < 0);
        assert_se(socket_address_parse(&a, "[a:b:1]:8888") < 0);

        assert_se(socket_address_parse(&a, "8888") >= 0);
        assert_se(a.sockaddr.sa.sa_family == (socket_ipv6_is_supported() ? AF_INET6 : AF_INET));

        assert_se(socket_address_parse(&a, "[2001:0db8:0000:85a3:0000:0000:ac1f:8001]:8888") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_INET6);

        assert_se(socket_address_parse(&a, "[::1]:8888") >= 0);
        assert_se(a.sockaddr.sa.sa_family == AF_INET6);

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

static void test_socket_address_is(void) {
        SocketAddress a;

        assert_se(socket_address_parse(&a, "192.168.1.1:8888") >= 0);
        assert_se(socket_address_is(&a, "192.168.1.1:8888", SOCK_STREAM));
        assert_se(!socket_address_is(&a, "route", SOCK_STREAM));
        assert_se(!socket_address_is(&a, "192.168.1.1:8888", SOCK_RAW));
}

static void test_socket_address_is_netlink(void) {
        SocketAddress a;

        assert_se(socket_address_parse_netlink(&a, "route 10") >= 0);
        assert_se(socket_address_is_netlink(&a, "route 10"));
        assert_se(!socket_address_is_netlink(&a, "192.168.1.1:8888"));
        assert_se(!socket_address_is_netlink(&a, "route 1"));
}

static void test_in_addr_is_null(void) {

        union in_addr_union i = {};

        assert_se(in_addr_is_null(AF_INET, &i) == true);
        assert_se(in_addr_is_null(AF_INET6, &i) == true);

        i.in.s_addr = 0x1000000;
        assert_se(in_addr_is_null(AF_INET, &i) == false);
        assert_se(in_addr_is_null(AF_INET6, &i) == false);

        assert_se(in_addr_is_null(-1, &i) == -EAFNOSUPPORT);
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

static void test_in_addr_to_string_one(int f, const char *addr) {
        union in_addr_union ua;
        _cleanup_free_ char *r = NULL;

        assert_se(in_addr_from_string(f, addr, &ua) >= 0);
        assert_se(in_addr_to_string(f, &ua, &r) >= 0);
        printf("test_in_addr_to_string_one: %s == %s\n", addr, r);
        assert_se(streq(addr, r));
}

static void test_in_addr_to_string(void) {
        test_in_addr_to_string_one(AF_INET, "192.168.0.1");
        test_in_addr_to_string_one(AF_INET, "10.11.12.13");
        test_in_addr_to_string_one(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        test_in_addr_to_string_one(AF_INET6, "::1");
        test_in_addr_to_string_one(AF_INET6, "fe80::");
}

static void *connect_thread(void *arg) {
        union sockaddr_union *sa = arg;
        _cleanup_close_ int fd = -1;

        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert_se(fd >= 0);

        assert_se(connect(fd, &sa->sa, sizeof(sa->in)) == 0);

        return NULL;
}

static void test_nameinfo_pretty(void) {
        _cleanup_free_ char *stdin_name = NULL, *localhost = NULL;

        union sockaddr_union s = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htonl(INADDR_ANY),
        };
        int r;

        union sockaddr_union c = {};
        socklen_t slen = sizeof(c.in), clen = sizeof(c.in);

        _cleanup_close_ int sfd = -1, cfd = -1;
        r = getnameinfo_pretty(STDIN_FILENO, &stdin_name);
        log_info_errno(r, "No connection remote: %m");

        assert_se(r < 0);

        sfd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(sfd >= 0);

        assert_se(bind(sfd, &s.sa, sizeof(s.in)) == 0);

        /* find out the port number */
        assert_se(getsockname(sfd, &s.sa, &slen) == 0);

        assert_se(listen(sfd, 1) == 0);

        assert_se(asynchronous_job(connect_thread, &s) == 0);

        log_debug("Accepting new connection on fd:%d", sfd);
        cfd = accept4(sfd, &c.sa, &clen, SOCK_CLOEXEC);
        assert_se(cfd >= 0);

        r = getnameinfo_pretty(cfd, &localhost);
        log_info("Connection from %s", localhost);
        assert_se(r == 0);
}

static void test_sockaddr_equal(void) {
        union sockaddr_union a = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htonl(INADDR_ANY),
        };
        union sockaddr_union b = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htonl(INADDR_ANY),
        };
        union sockaddr_union c = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htonl(1234),
        };
        union sockaddr_union d = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = 0,
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
        };
        assert_se(sockaddr_equal(&a, &a));
        assert_se(sockaddr_equal(&a, &b));
        assert_se(sockaddr_equal(&d, &d));
        assert_se(!sockaddr_equal(&a, &c));
        assert_se(!sockaddr_equal(&b, &c));
}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);

        test_socket_address_parse();
        test_socket_address_parse_netlink();
        test_socket_address_equal();
        test_socket_address_get_path();
        test_socket_address_is();
        test_socket_address_is_netlink();

        test_in_addr_is_null();
        test_in_addr_prefix_intersect();
        test_in_addr_prefix_next();
        test_in_addr_to_string();

        test_nameinfo_pretty();

        test_sockaddr_equal();

        return 0;
}
