/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <stdio.h>

#include "sd-netlink.h"

#include "af-list.h"
#include "alloc-util.h"
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

TEST(local_addresses_with_dummy) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        union in_addr_union u;
        int r, ifindex;

        ASSERT_OK(sd_netlink_open(&rtnl));

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

        /* Enable IPv6 for the case that it is disabled by default. */
        ASSERT_OK(sysctl_write_ip_property_boolean(AF_INET6, "test-local-addr", "disable_ipv6", false, /* shadow = */ NULL));

        /* Bring the interface up */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, ifindex));
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

        /* Cleanup */
        ASSERT_OK(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex));
        ASSERT_OK(sd_netlink_call(rtnl, message, 0, NULL));
        message = sd_netlink_message_unref(message);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
