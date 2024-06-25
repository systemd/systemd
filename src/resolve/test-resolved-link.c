/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/if.h>

#include "netlink-internal.h"
#include "resolved-link.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(LinkAddress*, link_address_free);

/* ================================================================
 * link_new()
 * ================================================================ */

TEST(link_new) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
}

/* ================================================================
 * link_process_rtnl()
 * ================================================================ */

TEST(link_process_rtnl) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *msg = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));

        ASSERT_OK(netlink_open_family(&nl, AF_INET));
        nl->protocol = NETLINK_ROUTE;

        ASSERT_OK(sd_rtnl_message_new_link(nl, &msg, RTM_NEWLINK, 1));
        message_seal(msg);

        ASSERT_OK(link_process_rtnl(link, msg));
}

/* ================================================================
 * link_relevant()
 * ================================================================ */

TEST(link_relevant) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *address = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));

        link->flags = IFF_LOOPBACK;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link->operstate = IF_OPER_UP;

        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        union in_addr_union ip = { .in.s_addr = htobe32(0xc0a84301) };
        union in_addr_union bcast = { .in.s_addr = htobe32(0xc0a843ff) };

        ASSERT_OK(link_address_new(link, &address, AF_INET, &ip, &bcast));

        ASSERT_TRUE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->is_managed = true;
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->networkd_operstate = LINK_OPERSTATE_DEGRADED_CARRIER;
        ASSERT_TRUE(link_relevant(link, AF_INET, false));
}

/* ================================================================
 * link_find_address()
 * ================================================================ */

TEST(link_find_address) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *v4addr = NULL, *v6addr = NULL, *ret_addr = NULL;

        union in_addr_union ipv4 = { .in.s_addr = htobe32(0xc0a84301) };
        union in_addr_union ipv6 = { .in6.s6_addr = { 0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e, 0x60, 0xbb } };

        ASSERT_OK(link_new(&manager, &link, 1));

        ASSERT_OK(link_address_new(link, &v4addr, AF_INET, &ipv4, &ipv4));
        ASSERT_OK(link_address_new(link, &v6addr, AF_INET6, &ipv6, &ipv6));

        ret_addr = link_find_address(link, AF_INET, &ipv4);
        ASSERT_TRUE(ret_addr == v4addr);

        ret_addr = link_find_address(link, AF_INET6, &ipv6);
        ASSERT_TRUE(ret_addr == v6addr);

        ret_addr = link_find_address(link, AF_INET6, &ipv4);
        ASSERT_NULL(ret_addr);
}

/* ================================================================
 * link_allocate_scopes()
 * ================================================================ */

TEST(link_allocate_scopes_resets_manager_dns_server) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *address = NULL;
        int ifindex = 1;

        union in_addr_union server_addr;
        _cleanup_free_ char *server_name;
        uint16_t server_port;
        _cleanup_(dns_server_unrefp) DnsServer *server;

        ASSERT_OK(link_new(&manager, &link, ifindex));
        link->flags = IFF_UP | IFF_LOWER_UP;
        link->operstate = IF_OPER_UP;

        union in_addr_union ipv4 = { .in.s_addr = htobe32(0xc0a84301) };
        ASSERT_OK(link_address_new(link, &address, AF_INET, &ipv4, &ipv4));

        server_addr.in.s_addr = htobe32(0x7f000001);
        server_name = strdup("localhost");
        server_port = 53;

        ASSERT_OK(dns_server_new(&manager, &server, DNS_SERVER_SYSTEM,
                        NULL, AF_INET, &server_addr, server_port, ifindex,
                        server_name, RESOLVE_CONFIG_SOURCE_DBUS));

        link->unicast_relevant = false;
        manager.dns_servers->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        manager.dns_servers->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        manager.dns_servers->received_udp_fragment_max = 1024u;

        link_allocate_scopes(link);

        ASSERT_TRUE(link->unicast_relevant);
        ASSERT_EQ(manager.dns_servers->verified_feature_level, _DNS_SERVER_FEATURE_LEVEL_INVALID);
        ASSERT_EQ(manager.dns_servers->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_BEST);
        ASSERT_EQ(manager.dns_servers->received_udp_fragment_max, DNS_PACKET_UNICAST_SIZE_MAX);

        ASSERT_FALSE(manager.dns_servers->packet_bad_opt);
        ASSERT_FALSE(manager.dns_servers->packet_rrsig_missing);
        ASSERT_FALSE(manager.dns_servers->packet_do_off);
        ASSERT_FALSE(manager.dns_servers->warned_downgrade);
}

TEST(link_allocate_scopes_resets_link_dns_server) {
        Manager manager = {};
        DnsServer *server;
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *address = NULL;
        int ifindex = 1;

        union in_addr_union server_addr;
        _cleanup_free_ char *server_name;
        uint16_t server_port;

        ASSERT_OK(link_new(&manager, &link, ifindex));
        link->flags = IFF_UP | IFF_LOWER_UP;
        link->operstate = IF_OPER_UP;

        union in_addr_union ipv4 = { .in.s_addr = htobe32(0xc0a84301) };
        ASSERT_OK(link_address_new(link, &address, AF_INET, &ipv4, &ipv4));

        server_addr.in.s_addr = htobe32(0x7f000001);
        server_name = strdup("localhost");
        server_port = 53;

        ASSERT_OK(dns_server_new(&manager, &server, DNS_SERVER_LINK,
                        link, AF_INET, &server_addr, server_port, ifindex,
                        server_name, RESOLVE_CONFIG_SOURCE_DBUS));

        link->unicast_relevant = true;
        link->dns_servers->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        link->dns_servers->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        link->dns_servers->received_udp_fragment_max = 1024u;

        link_allocate_scopes(link);

        ASSERT_TRUE(link->unicast_relevant);
        ASSERT_EQ(link->dns_servers->verified_feature_level, _DNS_SERVER_FEATURE_LEVEL_INVALID);
        ASSERT_EQ(link->dns_servers->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_BEST);
        ASSERT_EQ(link->dns_servers->received_udp_fragment_max, DNS_PACKET_UNICAST_SIZE_MAX);

        ASSERT_FALSE(link->dns_servers->packet_bad_opt);
        ASSERT_FALSE(link->dns_servers->packet_rrsig_missing);
        ASSERT_FALSE(link->dns_servers->packet_do_off);
        ASSERT_FALSE(link->dns_servers->warned_downgrade);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
