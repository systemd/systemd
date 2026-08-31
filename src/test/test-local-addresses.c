/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_tunnel.h>
#include <net/if.h>
#include <stdio.h>

#include "sd-netlink.h"

#include "af-list.h"
#include "alloc-util.h"
#include "errno-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "netlink-util.h"
#include "sysctl-util.h"
#include "tests.h"

static void print_local_addresses(const struct local_address *a, size_t n) {
        FOREACH_ARRAY(i, a, n)
                log_debug("%s ifindex=%i scope=%u priority=%"PRIu32" weight=%"PRIu32" address=%s",
                          af_to_name(i->family), i->ifindex, i->scope, i->priority, i->weight,
                          IN_ADDR_TO_STRING(i->family, &i->address));
}

static void delete_link_by_name(sd_netlink *rtnl, const char *ifname) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int ifindex;

        assert(rtnl);
        assert(ifname);

        ifindex = if_nametoindex(ifname);
        if (ifindex <= 0)
                return;

        if (sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex) < 0)
                return;

        (void) sd_netlink_call(rtnl, message, 0, NULL);
}

TEST(local_addresses) {
        struct local_address *a = NULL;
        int n;

        ASSERT_OK(n = local_addresses(NULL, 0, AF_INET, &a));
        log_debug("/* Local Addresses(ifindex:0, AF_INET) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_addresses(NULL, 0, AF_INET6, &a));
        log_debug("/* Local Addresses(ifindex:0, AF_INET6) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_addresses(NULL, 0, AF_UNSPEC, &a));
        log_debug("/* Local Addresses(ifindex:0, AF_UNSPEC) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_addresses(NULL, 1, AF_INET, &a));
        log_debug("/* Local Addresses(ifindex:1, AF_INET) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_addresses(NULL, 1, AF_INET6, &a));
        log_debug("/* Local Addresses(ifindex:1, AF_INET6) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_addresses(NULL, 1, AF_UNSPEC, &a));
        log_debug("/* Local Addresses(ifindex:1, AF_UNSPEC) */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_gateways(NULL, 0, AF_UNSPEC, &a));
        log_debug("/* Local Gateways */");
        print_local_addresses(a, n);
        a = mfree(a);

        ASSERT_OK(n = local_outbounds(NULL, 0, AF_UNSPEC, &a));
        log_debug("/* Local Outbounds */");
        print_local_addresses(a, n);
        free(a);
}

static void check_local_addresses(sd_netlink *rtnl, int ifindex, int request_ifindex, int family) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Addresses (ifindex:%i, %s) */", request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family));

        ASSERT_OK(n = local_addresses(rtnl, request_ifindex, family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.123.123", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET,
                                            .address = u,
                                    }),
                     IN_SET(family, AF_UNSPEC, AF_INET));

        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                     IN_SET(family, AF_UNSPEC, AF_INET6));

        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                     IN_SET(family, AF_UNSPEC, AF_INET6));
}

static void check_local_gateways(sd_netlink *rtnl, int ifindex, int request_ifindex, int family) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Gateways (ifindex:%i, %s) */", request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family));

        ASSERT_OK(n = local_gateways(rtnl, request_ifindex, family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.0.1", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET,
                                            .address = u,
                                    }),
                     IN_SET(family, AF_UNSPEC, AF_INET));

        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:0:123::1", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                  family == AF_UNSPEC);

        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                  IN_SET(family, AF_UNSPEC, AF_INET6));
}

static void check_no_local_gateway_with_priority(
                sd_netlink *rtnl,
                int request_ifindex,
                int family,
                uint32_t priority) {

        _cleanup_free_ struct local_address *a = NULL;
        int n;

        log_debug("/* Local Gateways (ifindex:%i, %s, unexpected_priority=%"PRIu32") */",
                  request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family), priority);

        ASSERT_OK(n = local_gateways(rtnl, request_ifindex, family, &a));
        print_local_addresses(a, n);

        FOREACH_ARRAY(i, a, n)
                ASSERT_NE(i->priority, priority);
}

static void check_no_local_gateway_address(
                sd_netlink *rtnl,
                int request_ifindex,
                int family,
                const char *address) {

        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Gateways (ifindex:%i, %s, unexpected_address=%s) */",
                  request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family), address);

        ASSERT_OK(n = local_gateways(rtnl, request_ifindex, family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(family, address, &u));

        FOREACH_ARRAY(i, a, n) {
                if (i->family != family)
                        continue;

                ASSERT_EQ(in_addr_equal(family, &i->address, &u), 0);
        }
}

static void check_local_gateway_peer(
                sd_netlink *rtnl,
                int ifindex,
                int request_ifindex,
                int request_family,
                uint32_t priority,
                uint32_t weight,
                int family,
                const char *peer,
                const char *prefsrc) {

        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union prefsrc_address, peer_address;
        int n;

        log_debug("/* Local Gateway Peer (ifindex:%i, %s, priority=%"PRIu32", weight=%"PRIu32", "
                  "expected_family=%s) */",
                  request_ifindex, request_family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(request_family),
                  priority, weight, af_to_name(family));

        ASSERT_OK(n = local_gateways(rtnl, request_ifindex, request_family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(family, peer, &peer_address));
        if (prefsrc)
                ASSERT_OK(in_addr_from_string(family, prefsrc, &prefsrc_address));

        bool found = false;
        FOREACH_ARRAY(i, a, n) {
                if (i->ifindex != ifindex || i->family != family || i->priority != priority)
                        continue;
                if (i->weight != weight)
                        continue;
                if (in_addr_equal(family, &i->address, &peer_address) <= 0)
                        continue;

                if (prefsrc)
                        ASSERT_OK_POSITIVE(in_addr_equal(family, &i->prefsrc, &prefsrc_address));
                else
                        ASSERT_FALSE(in_addr_is_set(family, &i->prefsrc));

                found = true;
                break;
        }

        ASSERT_TRUE(found);
}

static void check_local_outbounds(sd_netlink *rtnl, int ifindex, int request_ifindex, int family, const char *ipv6_expected) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Outbounds (ifindex:%i, %s, expected_ipv6_address=%s) */",
                  request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family), ipv6_expected);

        ASSERT_OK(n = local_outbounds(rtnl, request_ifindex, family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.123.123", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET,
                                            .address = u,
                                    }),
                  IN_SET(family, AF_UNSPEC, AF_INET));

        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                  family == AF_UNSPEC);

        ASSERT_OK(in_addr_from_string(AF_INET6, ipv6_expected, &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET6,
                                            .address = u,
                                    }),
                  IN_SET(family, AF_UNSPEC, AF_INET6));
}

static void check_local_outbound_address(
                sd_netlink *rtnl,
                int request_ifindex,
                int request_family,
                int address_ifindex,
                int address_family,
                const char *address,
                bool expected) {

        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Outbounds (ifindex:%i, %s, %s_address=%s) */",
                  request_ifindex, request_family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(request_family),
                  expected ? "expected" : "unexpected", address);

        ASSERT_OK(n = local_outbounds(rtnl, request_ifindex, request_family, &a));
        print_local_addresses(a, n);

        ASSERT_OK(in_addr_from_string(address_family, address, &u));
        ASSERT_EQ(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = address_ifindex,
                                            .family = address_family,
                                            .address = u,
                                    }),
                  expected);
}

TEST(local_addresses_with_dummy) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        union in_addr_union u;
        int ifindex, ifindex2, p2p_ifindex = 0, p2p_ifindex2 = 0, r;

        ASSERT_OK(sd_netlink_open(&rtnl));

        delete_link_by_name(rtnl, "test-ipip2");
        delete_link_by_name(rtnl, "test-ipip");
        delete_link_by_name(rtnl, "test-local-a2");
        delete_link_by_name(rtnl, "test-local-addr");

        /* Create a dummy interface */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-addr"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy"));
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("dummy network interface is not supported");
        ASSERT_OK(r);
        message = sd_netlink_message_unref(message);

        /* Get ifindex */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-addr"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, &reply));
        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &ifindex));
        ASSERT_GT(ifindex, 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        /* Create a second dummy interface */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-a2"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Get second ifindex */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-a2"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, &reply));
        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &ifindex2));
        ASSERT_GT(ifindex2, 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        /* Enable IPv6 for the case that it is disabled by default. */
        ASSERT_OK(sysctl_write_ip_property_boolean(AF_INET6, "test-local-addr", "disable_ipv6", false, /* shadow= */ NULL));

        /* Bring the interface up */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, ifindex));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Bring the second interface up */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, ifindex2));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 address */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 16));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.123.123", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.255.255", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_BROADCAST, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add IPv6 addresses */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 64));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 64));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 default gateway (RTA_GATEWAY) */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.0.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, RTA_GATEWAY, &u.in));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 default gateway (RTA_VIA) */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:0:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_data(message, RTA_VIA,
                                                 &(RouteVia) {
                                                         .family = AF_INET6,
                                                         .address = u,
                                                 }, sizeof(RouteVia)));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add an IPv6 default gateway */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add default routes without explicit gateways. Without peer addresses, these must not be
         * reported. */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2345));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2345));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        check_no_local_gateway_with_priority(rtnl, 0, AF_UNSPEC, 2345);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 2345);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET6, 2345);
        check_no_local_gateway_with_priority(rtnl, ifindex, AF_UNSPEC, 2345);
        check_no_local_gateway_with_priority(rtnl, ifindex, AF_INET, 2345);
        check_no_local_gateway_with_priority(rtnl, ifindex, AF_INET6, 2345);

        /* Check */
        check_local_addresses(rtnl, ifindex, 0, AF_UNSPEC);
        check_local_addresses(rtnl, ifindex, 0, AF_INET);
        check_local_addresses(rtnl, ifindex, 0, AF_INET6);
        check_local_addresses(rtnl, ifindex, ifindex, AF_UNSPEC);
        check_local_addresses(rtnl, ifindex, ifindex, AF_INET);
        check_local_addresses(rtnl, ifindex, ifindex, AF_INET6);
        check_local_gateways(rtnl, ifindex, 0, AF_UNSPEC);
        check_local_gateways(rtnl, ifindex, 0, AF_INET);
        check_local_gateways(rtnl, ifindex, 0, AF_INET6);
        check_local_gateways(rtnl, ifindex, ifindex, AF_UNSPEC);
        check_local_gateways(rtnl, ifindex, ifindex, AF_INET);
        check_local_gateways(rtnl, ifindex, ifindex, AF_INET6);
        check_local_outbounds(rtnl, ifindex, 0, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET6, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET6, "2001:db8:1:123::123");

        /* Add one more IPv6 address. */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 64));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::124", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Replace the previous IPv6 default gateway with one with preferred source address. */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_DELROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Check again. */
        check_local_outbounds(rtnl, ifindex, 0, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET6, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET6, "2001:db8:1:123::123");

        /* Replace the preferred source address. */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_DELROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:1:123::124", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Check again. */
        check_local_outbounds(rtnl, ifindex, 0, AF_UNSPEC, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET6, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_UNSPEC, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET6, "2001:db8:1:123::124");

        /* Create a point-to-point IPIP interface. */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-ipip"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "ipip"));
        ASSERT_OK(sd_netlink_message_open_container_union(message, IFLA_INFO_DATA, "ipip"));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFLA_IPTUN_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFLA_IPTUN_REMOTE, &u.in));
        ASSERT_OK(sd_netlink_message_close_container(message));
        ASSERT_OK(sd_netlink_message_close_container(message));
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_debug_errno(r, "IPIP tunnel is not supported, skipping point-to-point gateway tests: %m");
                message = sd_netlink_message_unref(message);
                goto finish;
        }
        ASSERT_OK(r);
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-ipip"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, &reply));
        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &p2p_ifindex));
        ASSERT_GT(p2p_ifindex, 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, p2p_ifindex));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Enable IPv6 for the case that it is disabled by default. */
        ASSERT_OK(sysctl_write_ip_property_boolean(AF_INET6, "test-ipip", "disable_ipv6", false, /* shadow= */ NULL));

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-ipip2"));
        ASSERT_OK(sd_netlink_message_open_container(message, IFLA_LINKINFO));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "ipip"));
        ASSERT_OK(sd_netlink_message_open_container_union(message, IFLA_INFO_DATA, "ipip"));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.3", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFLA_IPTUN_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.4", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFLA_IPTUN_REMOTE, &u.in));
        ASSERT_OK(sd_netlink_message_close_container(message));
        ASSERT_OK(sd_netlink_message_close_container(message));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0));
        ASSERT_OK(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-ipip2"));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, &reply));
        ASSERT_OK(sd_rtnl_message_link_get_ifindex(reply, &p2p_ifindex2));
        ASSERT_GT(p2p_ifindex2, 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, p2p_ifindex2));
        ASSERT_OK(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add point-to-point addresses and check that the peer endpoints back the gateway-less routes. */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.124.0.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.124.0.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.124.0.3", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.124.0.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex2, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2351));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, ifindex2));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 128));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:2:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:2:123::2", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_ADDRESS, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 128));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::2", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_ADDRESS, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_message_append_cache_info(message, IFA_CACHEINFO,
                                                       &(struct ifa_cacheinfo) {
                                                               .ifa_prefered = 0,
                                                               .ifa_valid = UINT32_MAX,
                                                       }));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 128));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::3", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(in_addr_from_string(AF_INET6, "::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_ADDRESS, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex, AF_INET6));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 128));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::4", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6));
        ASSERT_OK(in_addr_from_string(AF_INET6, "ff02::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, IFA_ADDRESS, &u.in6));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2347));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2352));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::3", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 2346));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:3:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        bool have_multipath = true;
        uint32_t gatewayless_priority = 3344, gatewayless_weight = 17;
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, gatewayless_priority));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_data(message, RTA_MULTIPATH,
                                                 ((struct rtnexthop[]) {
                                                         {
                                                                 .rtnh_len = sizeof(struct rtnexthop),
                                                                 .rtnh_ifindex = p2p_ifindex,
                                                                 .rtnh_hops = gatewayless_weight,
                                                         },
                                                         {
                                                                 .rtnh_len = sizeof(struct rtnexthop),
                                                                 .rtnh_ifindex = ifindex2,
                                                                 .rtnh_hops = 3,
                                                         },
                                                 }), 2 * sizeof(struct rtnexthop)));
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (r == -EINVAL) {
                log_debug_errno(r, "Multipath routes are not supported, using single-path fallback: %m");
                have_multipath = false;
                gatewayless_priority = 3343;
                gatewayless_weight = 0;
        } else
                ASSERT_OK(r);
        message = sd_netlink_message_unref(message);

        if (!have_multipath) {
                ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
                ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
                ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
                ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, gatewayless_priority));
                ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
                ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
                ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
                message = sd_netlink_message_unref(message);
        }

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3346));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.124.0.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, RTA_PREFSRC, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3347));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.123.123", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, RTA_PREFSRC, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3348));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(in_addr_from_string(AF_INET6, "2001:db8:4:123::1", &u));
        ASSERT_OK(sd_netlink_message_append_data(message, RTA_VIA,
                                                 &(RouteVia) {
                                                         .family = AF_INET6,
                                                         .address = u,
                                                 }, sizeof(RouteVia)));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3349));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3350));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.123.123.123", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, RTA_PREFSRC, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add a gateway-less default route for p2p_ifindex2 so it becomes a candidate link.
         * This makes the address scan actually reach that interface and exercise both the
         * broadcast rejection (255.255.255.255) and ambiguity detection (two different peers). */
        ASSERT_OK(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC));
        ASSERT_OK(sd_rtnl_message_route_set_scope(message, RT_SCOPE_LINK));
        ASSERT_OK(sd_rtnl_message_route_set_type(message, RTN_UNICAST));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_PRIORITY, 3351));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN));
        ASSERT_OK(sd_netlink_message_append_u32(message, RTA_OIF, p2p_ifindex2));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add a valid p2p address on p2p_ifindex2: 10.125.0.1 -> 10.125.0.2 */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex2, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.1", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add a second valid p2p address with a different peer: 10.125.0.4 -> 10.126.0.2
         * This creates ambiguity (two different peers on the same link/family), so no
         * synthetic gateway should be published for p2p_ifindex2. */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex2, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.4", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.126.0.2", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        /* Add a third p2p address with a broadcast peer: 10.125.0.3 -> 255.255.255.255
         * This exercises the INADDR_BROADCAST rejection path. */
        ASSERT_OK(sd_rtnl_message_new_addr_update(rtnl, &message, p2p_ifindex2, AF_INET));
        ASSERT_OK(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE));
        ASSERT_OK(sd_rtnl_message_addr_set_prefixlen(message, 32));
        ASSERT_OK(in_addr_from_string(AF_INET, "10.125.0.3", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in));
        ASSERT_OK(in_addr_from_string(AF_INET, "255.255.255.255", &u));
        ASSERT_OK(sd_netlink_message_append_in_addr(message, IFA_ADDRESS, &u.in));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        check_local_gateway_peer(
                        rtnl, p2p_ifindex, 0, AF_UNSPEC, gatewayless_priority, gatewayless_weight,
                        AF_INET, "10.124.0.2", NULL);
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, p2p_ifindex, AF_UNSPEC, gatewayless_priority, gatewayless_weight,
                        AF_INET, "10.124.0.2", NULL);
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, 0, AF_INET, gatewayless_priority, gatewayless_weight,
                        AF_INET, "10.124.0.2", NULL);
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, p2p_ifindex, AF_INET, gatewayless_priority, gatewayless_weight,
                        AF_INET, "10.124.0.2", NULL);
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, 0, AF_UNSPEC, 3348, 0,
                        AF_INET6, "2001:db8:4:123::1", NULL);
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, p2p_ifindex, AF_UNSPEC, 3348, 0,
                        AF_INET6, "2001:db8:4:123::1", NULL);
        check_local_gateway_peer(rtnl, p2p_ifindex, 0, AF_INET, 3346, 0, AF_INET, "10.124.0.2", "10.124.0.1");
        check_local_gateway_peer(
                        rtnl, p2p_ifindex, p2p_ifindex, AF_INET, 3346, 0, AF_INET, "10.124.0.2", "10.124.0.1");
        check_no_local_gateway_with_priority(rtnl, 0, AF_UNSPEC, 2347);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_UNSPEC, 2347);
        check_no_local_gateway_with_priority(rtnl, 0, AF_UNSPEC, 2345);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_UNSPEC, 2345);
        check_no_local_gateway_with_priority(rtnl, 0, AF_UNSPEC, 3349);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_UNSPEC, 3349);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 3348);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_INET, 3348);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 3349);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_INET, 3349);
        check_local_gateway_peer(rtnl, p2p_ifindex, 0, AF_INET6, 2346, 0,
                                 AF_INET6, "2001:db8:3:123::2", "2001:db8:3:123::1");
        check_local_gateway_peer(rtnl, p2p_ifindex, p2p_ifindex, AF_INET6, 2346, 0,
                                 AF_INET6, "2001:db8:3:123::2", "2001:db8:3:123::1");
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 3347);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_INET, 3347);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 2351);
        check_no_local_gateway_with_priority(rtnl, ifindex2, AF_INET, 2351);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET, 3350);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_INET, 3350);
        check_no_local_gateway_with_priority(rtnl, 0, AF_INET6, 2352);
        check_no_local_gateway_with_priority(rtnl, p2p_ifindex, AF_INET6, 2352);
        check_no_local_gateway_address(rtnl, 0, AF_INET, "10.125.0.2");
        /* p2p_ifindex2 has two valid but different peers (10.125.0.2 and 10.126.0.2), so
         * it should be marked ambiguous and no gateway should be synthesized. */
        check_no_local_gateway_address(rtnl, p2p_ifindex2, AF_INET, "10.125.0.2");
        check_no_local_gateway_address(rtnl, 0, AF_INET, "10.126.0.2");
        check_no_local_gateway_address(rtnl, p2p_ifindex, AF_INET, "10.126.0.2");
        check_no_local_gateway_address(rtnl, p2p_ifindex2, AF_INET, "10.126.0.2");
        /* 255.255.255.255 should never be published as a gateway (broadcast address). */
        check_no_local_gateway_address(rtnl, 0, AF_INET, "255.255.255.255");
        check_no_local_gateway_address(rtnl, p2p_ifindex2, AF_INET, "255.255.255.255");
        /* ::1 and ff02::1 should never be published (localhost and multicast). */
        check_no_local_gateway_address(rtnl, 0, AF_INET6, "::1");
        check_no_local_gateway_address(rtnl, p2p_ifindex, AF_INET6, "::1");
        check_no_local_gateway_address(rtnl, 0, AF_INET6, "ff02::1");
        check_no_local_gateway_address(rtnl, p2p_ifindex, AF_INET6, "ff02::1");
        check_local_outbound_address(rtnl, 0, AF_INET, p2p_ifindex, AF_INET, "10.124.0.1", true);
        check_local_outbound_address(rtnl, p2p_ifindex, AF_INET, p2p_ifindex, AF_INET, "10.124.0.1", true);
        check_local_outbound_address(rtnl, 0, AF_INET6, p2p_ifindex, AF_INET6, "2001:db8:2:123::1", false);
        check_local_outbound_address(rtnl, p2p_ifindex, AF_INET6, p2p_ifindex, AF_INET6, "2001:db8:2:123::1", false);
        check_local_outbound_address(rtnl, 0, AF_INET6, p2p_ifindex, AF_INET6, "2001:db8:3:123::1", false);
        check_local_outbound_address(rtnl, p2p_ifindex, AF_INET6, p2p_ifindex, AF_INET6, "2001:db8:3:123::1", false);

finish:
        /* Cleanup */
        if (p2p_ifindex2 > 0) {
                ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, p2p_ifindex2));
                ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
                message = sd_netlink_message_unref(message);
        }

        if (p2p_ifindex > 0) {
                ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, p2p_ifindex));
                ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
                message = sd_netlink_message_unref(message);
        }

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex2));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);

        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
