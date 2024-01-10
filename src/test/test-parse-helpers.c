/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/in.h>
#include <sys/socket.h>
#include <stdio.h>

#include "macro.h"
#include "parse-helpers.h"
#include "tests.h"

static void test_valid_item(
                const char *str,
                int expected_af,
                int expected_ip_protocol,
                uint16_t expected_nr_ports,
                uint16_t expected_port_min) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) >= 0);
        assert_se(af == expected_af);
        assert_se(ip_protocol == expected_ip_protocol);
        assert_se(nr_ports == expected_nr_ports);
        assert_se(port_min == expected_port_min);

        log_info("%s: \"%s\" ok", __func__, str);
}

static void test_invalid_item(const char *str) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) == -EINVAL);

        log_info("%s: \"%s\" ok", __func__, str);
}

TEST(valid_items) {
        test_valid_item("any", AF_UNSPEC, 0, 0, 0);
        test_valid_item("0-65535", AF_UNSPEC, 0, 0, 0);
        test_valid_item("ipv4", AF_INET, 0, 0, 0);
        test_valid_item("ipv6", AF_INET6, 0, 0, 0);
        test_valid_item("ipv4:any", AF_INET, 0, 0, 0);
        test_valid_item("ipv6:any", AF_INET6, 0, 0, 0);
        test_valid_item("tcp", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("tcp:any", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp:any", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("0", AF_UNSPEC, 0, 1, 0);
        test_valid_item("6666", AF_UNSPEC, 0, 1, 6666);
        test_valid_item("6666-6667", AF_UNSPEC, 0, 2, 6666);
        test_valid_item("65535", AF_UNSPEC, 0, 1, 65535);
        test_valid_item("1-65535", AF_UNSPEC, 0, 65535, 1);
        test_valid_item("ipv4:tcp", AF_INET, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv4:udp", AF_INET, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv6:tcp", AF_INET6, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv6:udp", AF_INET6, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv4:6666", AF_INET, 0, 1, 6666);
        test_valid_item("ipv6:6666", AF_INET6, 0, 1, 6666);
        test_valid_item("tcp:6666", AF_UNSPEC, IPPROTO_TCP, 1, 6666);
        test_valid_item("udp:6666", AF_UNSPEC, IPPROTO_UDP, 1, 6666);
        test_valid_item("ipv4:tcp:6666", AF_INET, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:tcp:6666", AF_INET6, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:udp:6666-6667", AF_INET6, IPPROTO_UDP, 2, 6666);
        test_valid_item("ipv6:tcp:any", AF_INET6, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv6:tcp:0", AF_INET6, IPPROTO_TCP, 1, 0);
}

TEST(invalid_items) {
        test_invalid_item("");
        test_invalid_item(":");
        test_invalid_item("::");
        test_invalid_item("any:");
        test_invalid_item("meh");
        test_invalid_item("zupa:meh");
        test_invalid_item("zupa:meh:eh");
        test_invalid_item("ip");
        test_invalid_item("dccp");
        test_invalid_item("ipv6meh");
        test_invalid_item("ipv6::");
        test_invalid_item("ipv6:ipv6");
        test_invalid_item("ipv6:icmp");
        test_invalid_item("65536");
        test_invalid_item("ipv6:tcp:6666-6665");
        test_invalid_item("ipv6:tcp:6666-100000");
        test_invalid_item("ipv6::6666");
        test_invalid_item("ipv6:tcp:any:");
        test_invalid_item("ipv6:tcp:any:ipv6");
        test_invalid_item("ipv6:tcp:6666:zupa");
        test_invalid_item("ipv6:tcp:6666:any");
        test_invalid_item("ipv6:tcp:6666 zupa");
        test_invalid_item("ipv6:tcp:6666: zupa");
        test_invalid_item("ipv6:tcp:6666\n zupa");
}

DEFINE_TEST_MAIN(LOG_INFO);
