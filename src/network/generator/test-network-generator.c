/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "network-generator.h"
#include "string-util.h"
#include "tests.h"

static void test_network_one(const char *ifname, const char *key, const char *value, const char *expected) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_free_ char *output = NULL;
        Network *network;

        log_debug("/* %s(%s=%s) */", __func__, key, value);

        ASSERT_OK(parse_cmdline_item(key, value, &context));
        ASSERT_NOT_NULL(network = network_get(&context, ifname));
        ASSERT_OK(network_format(network, &output));
        ASSERT_STREQ(output, expected);
}

static void test_network_two(const char *ifname,
                             const char *key1, const char *value1,
                             const char *key2, const char *value2,
                             const char *expected) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_free_ char *output = NULL;
        Network *network;

        log_debug("/* %s(%s=%s, %s=%s) */", __func__, key1, value1, key2, value2);

        ASSERT_OK(parse_cmdline_item(key1, value1, &context));
        ASSERT_OK(parse_cmdline_item(key2, value2, &context));
        ASSERT_OK(context_merge_networks(&context));
        ASSERT_NOT_NULL(network = network_get(&context, ifname));
        ASSERT_OK(network_format(network, &output));
        ASSERT_STREQ(output, expected);
}

static void test_netdev_one(const char *ifname, const char *key, const char *value, const char *expected) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_free_ char *output = NULL;
        NetDev *netdev;

        log_debug("/* %s(%s=%s) */", __func__, key, value);

        ASSERT_OK(parse_cmdline_item(key, value, &context));
        ASSERT_NOT_NULL(netdev = netdev_get(&context, ifname));
        ASSERT_OK(netdev_format(netdev, &output));
        ASSERT_STREQ(output, expected);
}

static void test_link_one(const char *filename, const char *key, const char *value, const char *expected) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_free_ char *output = NULL;
        Link *link;

        log_debug("/* %s(%s=%s) */", __func__, key, value);

        ASSERT_OK(parse_cmdline_item(key, value, &context));
        ASSERT_NOT_NULL(link = link_get(&context, filename));
        ASSERT_OK(link_format(link, &output));
        ASSERT_STREQ(output, expected);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_network_one("", "ip", "dhcp6",
                         "[Match]\n"
                         "Kind=!*\n"
                         "Type=!loopback\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=ipv6\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "ip", "eth0:dhcp",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=ipv4\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "ip", "eth0:dhcp:1530",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "MTUBytes=1530\n"
                         "\n[Network]\n"
                         "DHCP=ipv4\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "ip", "eth0:dhcp:1530:00:11:22:33:44:55",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "MACAddress=00:11:22:33:44:55\n"
                         "MTUBytes=1530\n"
                         "\n[Network]\n"
                         "DHCP=ipv4\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "ip", "10.99.37.44::10.99.10.1:255.255.0.0::eth0:off",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=no\n"
                         "LinkLocalAddressing=no\n"
                         "IPv6AcceptRA=no\n"
                         "\n[DHCP]\n"
                         "\n[Address]\n"
                         "Address=10.99.37.44/16\n"
                         "\n[Route]\n"
                         "Gateway=10.99.10.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10::192.168.0.1:255.255.255.0:hogehoge:eth0:on",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:1530",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "MTUBytes=1530\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:1530:00:11:22:33:44:55",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "MACAddress=00:11:22:33:44:55\n"
                         "MTUBytes=1530\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10:10.10.10.11",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "DNS=10.10.10.11\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_one("eth0", "ip", "[2001:1234:56:8f63::10]::[2001:1234:56:8f63::1]:64:hogehoge:eth0:on",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=2001:1234:56:8f63::10/64\n"
                         "\n[Route]\n"
                         "Gateway=2001:1234:56:8f63::1\n"
                         );

        test_network_one("eth0", "ip", "[2001:1234:56:8f63::10]:[2001:1234:56:8f63::2]:[2001:1234:56:8f63::1]:64:hogehoge:eth0:on",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=2001:1234:56:8f63::10/64\n"
                         "Peer=2001:1234:56:8f63::2\n"
                         "\n[Route]\n"
                         "Gateway=2001:1234:56:8f63::1\n"
                         );

        test_network_one("", "rd.route", "10.1.2.3/16:10.0.2.3",
                         "[Match]\n"
                         "Kind=!*\n"
                         "Type=!loopback\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "\n[DHCP]\n"
                         "\n[Route]\n"
                         "Destination=10.1.2.3/16\n"
                         "Gateway=10.0.2.3\n"
                         );

        test_network_one("eth0", "rd.route", "10.1.2.3/16:10.0.2.3:eth0",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "\n[DHCP]\n"
                         "\n[Route]\n"
                         "Destination=10.1.2.3/16\n"
                         "Gateway=10.0.2.3\n"
                         );

        test_network_one("", "nameserver", "10.1.2.3",
                         "[Match]\n"
                         "Kind=!*\n"
                         "Type=!loopback\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DNS=10.1.2.3\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("", "rd.peerdns", "0",
                         "[Match]\n"
                         "Kind=!*\n"
                         "Type=!loopback\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "\n[DHCP]\n"
                         "UseDNS=no\n"
                         );

        test_network_one("", "rd.peerdns", "1",
                         "[Match]\n"
                         "Kind=!*\n"
                         "Type=!loopback\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "\n[DHCP]\n"
                         "UseDNS=yes\n"
                         );

        test_network_two("eth0", "vlan", "vlan99:eth0", "vlan", "vlan98:eth0",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "VLAN=vlan99\n"
                         "VLAN=vlan98\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "bridge", "bridge99:eth0,eth1",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "Bridge=bridge99\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth1", "bridge", "bridge99:eth0,eth1",
                         "[Match]\n"
                         "Name=eth1\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "Bridge=bridge99\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth0", "bond", "bond99:eth0,eth1",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "Bond=bond99\n"
                         "\n[DHCP]\n"
                         );

        test_network_one("eth1", "bond", "bond99:eth0,eth1::1530",
                         "[Match]\n"
                         "Name=eth1\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "Bond=bond99\n"
                         "\n[DHCP]\n"
                         );

        test_netdev_one("bridge99", "bridge", "bridge99:",
                        "[NetDev]\n"
                        "Kind=bridge\n"
                        "Name=bridge99\n"
                        );

        test_netdev_one("bridge99", "bridge", "bridge99:,,,",
                        "[NetDev]\n"
                        "Kind=bridge\n"
                        "Name=bridge99\n"
                        );

        test_netdev_one("bond99", "bond", "bond99:",
                        "[NetDev]\n"
                        "Kind=bond\n"
                        "Name=bond99\n"
                        );

        test_netdev_one("bond99", "bond", "bond99::hogehoge:1530",
                        "[NetDev]\n"
                        "Kind=bond\n"
                        "Name=bond99\n"
                        "MTUBytes=1530\n"
                        );

        test_netdev_one("bond99", "bond", "bond99:eth0,eth1::1530",
                        "[NetDev]\n"
                        "Kind=bond\n"
                        "Name=bond99\n"
                        "MTUBytes=1530\n"
                        );

        test_netdev_one("vlan123", "vlan", "vlan123:eth0",
                        "[NetDev]\n"
                        "Kind=vlan\n"
                        "Name=vlan123\n"
                        "\n[VLAN]\n"
                        "Id=123\n"
                        );

        test_netdev_one("vlan0013", "vlan", "vlan0013:eth0",
                        "[NetDev]\n"
                        "Kind=vlan\n"
                        "Name=vlan0013\n"
                        "\n[VLAN]\n"
                        "Id=11\n" /* 0013 (octal) -> 11 */
                        );

        test_netdev_one("eth0.123", "vlan", "eth0.123:eth0",
                        "[NetDev]\n"
                        "Kind=vlan\n"
                        "Name=eth0.123\n"
                        "\n[VLAN]\n"
                        "Id=123\n"
                        );

        test_netdev_one("eth0.0013", "vlan", "eth0.0013:eth0",
                        "[NetDev]\n"
                        "Kind=vlan\n"
                        "Name=eth0.0013\n"
                        "\n[VLAN]\n"
                        "Id=11\n" /* 0013 (octal) -> 11 */
                        );

        test_link_one("hogehoge", "ifname", "hogehoge:00:11:22:33:44:55",
                      "[Match]\n"
                      "MACAddress=00:11:22:33:44:55\n"
                      "\n[Link]\n"
                      "Name=hogehoge\n"
                      );

        test_link_one("001122334455", "net.ifname-policy", "keep,kernel,database,onboard,slot,path,mac,00:11:22:33:44:55",
                      "[Match]\n"
                      "MACAddress=00:11:22:33:44:55\n"
                      "\n[Link]\n"
                      "NamePolicy=keep kernel database onboard slot path mac\n"
                      "AlternativeNamesPolicy=database onboard slot path mac\n"
                      );

        test_link_one("default", "net.ifname-policy", "keep,kernel,database,onboard,slot,path,mac",
                      "[Match]\n"
                      "OriginalName=*\n"
                      "\n[Link]\n"
                      "NamePolicy=keep kernel database onboard slot path mac\n"
                      "AlternativeNamesPolicy=database onboard slot path mac\n"
                      );

        test_network_two("eth0",
                         "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10:10.10.10.11",
                         "rd.route", "10.1.2.3/16:10.0.2.3",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "DNS=10.10.10.11\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Destination=10.1.2.3/16\n"
                         "Gateway=10.0.2.3\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_two("eth0",
                         "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on",
                         "nameserver", "10.1.2.3",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.1.2.3\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_two("eth0",
                         "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10:10.10.10.11",
                         "nameserver", "10.1.2.3",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "DNS=10.10.10.11\n"
                         "DNS=10.1.2.3\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_two("eth0",
                         "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10:10.10.10.11",
                         "rd.peerdns", "1",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "DNS=10.10.10.11\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "UseDNS=yes\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        test_network_two("eth0",
                         "ip", "192.168.0.10:192.168.0.2:192.168.0.1:255.255.255.0:hogehoge:eth0:on:10.10.10.10:10.10.10.11",
                         "bridge", "bridge99:eth0,eth1",
                         "[Match]\n"
                         "Name=eth0\n"
                         "\n[Link]\n"
                         "\n[Network]\n"
                         "DHCP=yes\n"
                         "DNS=10.10.10.10\n"
                         "DNS=10.10.10.11\n"
                         "Bridge=bridge99\n"
                         "\n[DHCP]\n"
                         "Hostname=hogehoge\n"
                         "\n[Address]\n"
                         "Address=192.168.0.10/24\n"
                         "Peer=192.168.0.2\n"
                         "\n[Route]\n"
                         "Gateway=192.168.0.1\n"
                         );

        return 0;
}
