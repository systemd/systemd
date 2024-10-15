/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/if.h>
#include <stdio.h>

#include "af-list.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "netlink-util.h"
#include "tests.h"

static bool support_rta_via = false;

static void print_local_addresses(const struct local_address *a, size_t n) {
        FOREACH_ARRAY(i, a, n)
                log_debug("%s ifindex=%i scope=%u priority=%"PRIu32" weight=%"PRIu32" address=%s",
                          af_to_name(i->family), i->ifindex, i->scope, i->priority, i->weight,
                          IN_ADDR_TO_STRING(i->family, &i->address));
}

TEST(local_addresses) {
        struct local_address *a = NULL;
        int n;

        n = local_addresses(NULL, 0, AF_INET, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_INET) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_addresses(NULL, 0, AF_INET6, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_INET6) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_addresses(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_UNSPEC) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_INET, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_INET) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_INET6, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_INET6) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_UNSPEC) */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_gateways(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Gateways */");
        print_local_addresses(a, n);
        a = mfree(a);

        n = local_outbounds(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Outbounds */");
        print_local_addresses(a, n);
        free(a);
}

static void check_local_addresses(sd_netlink *rtnl, int ifindex, int request_ifindex, int family) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Addresses (ifindex:%i, %s) */", request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family));

        n = local_addresses(rtnl, request_ifindex, family, &a);
        assert_se(n >= 0);
        print_local_addresses(a, n);

        assert_se(in_addr_from_string(AF_INET, "10.123.123.123", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET6));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .scope = RT_SCOPE_UNIVERSE,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET6));
}

static void check_local_gateways(sd_netlink *rtnl, int ifindex, int request_ifindex, int family) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Gateways (ifindex:%i, %s) */", request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family));

        n = local_gateways(rtnl, request_ifindex, family, &a);
        assert_se(n >= 0);
        print_local_addresses(a, n);

        assert_se(in_addr_from_string(AF_INET, "10.123.0.1", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8:0:123::1", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == (family == AF_UNSPEC && support_rta_via));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .priority = 1234,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET6));
}

static void check_local_outbounds(sd_netlink *rtnl, int ifindex, int request_ifindex, int family, const char *ipv6_expected) {
        _cleanup_free_ struct local_address *a = NULL;
        union in_addr_union u;
        int n;

        log_debug("/* Local Outbounds (ifindex:%i, %s, expected_ipv6_address=%s) */",
                  request_ifindex, family == AF_UNSPEC ? "AF_UNSPEC" : af_to_name(family), ipv6_expected);

        n = local_outbounds(rtnl, request_ifindex, family, &a);
        assert_se(n >= 0);
        print_local_addresses(a, n);

        assert_se(in_addr_from_string(AF_INET, "10.123.123.123", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET));

        assert_se(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == (family == AF_UNSPEC && support_rta_via));

        assert_se(in_addr_from_string(AF_INET6, ipv6_expected, &u) >= 0);
        assert_se(has_local_address(a, n,
                                    &(struct local_address) {
                                            .ifindex = ifindex,
                                            .family = AF_INET6,
                                            .address = u,
                                    }) == IN_SET(family, AF_UNSPEC, AF_INET6));
}

TEST(local_addresses_with_dummy) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        union in_addr_union u;
        int r, ifindex;

        assert_se(sd_netlink_open(&rtnl) >= 0);

        /* Create a dummy interface */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_NEWLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-addr") >= 0);
        assert_se(sd_netlink_message_open_container(message, IFLA_LINKINFO) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_INFO_KIND, "dummy") >= 0);
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");
        if (r == -EOPNOTSUPP)
                return (void) log_tests_skipped("dummy network interface is not supported");
        assert_se(r >= 0);
        message = sd_netlink_message_unref(message);

        /* Get ifindex */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(message, IFLA_IFNAME, "test-local-addr") >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, &reply) >= 0);
        assert_se(sd_rtnl_message_link_get_ifindex(reply, &ifindex) >= 0);
        assert_se(ifindex > 0);
        message = sd_netlink_message_unref(message);
        reply = sd_netlink_message_unref(reply);

        /* Bring the interface up */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_SETLINK, ifindex) >= 0);
        assert_se(sd_rtnl_message_link_set_flags(message, IFF_UP, IFF_UP) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 address */
        assert_se(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET) >= 0);
        assert_se(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_addr_set_prefixlen(message, 16) >= 0);
        assert_se(in_addr_from_string(AF_INET, "10.123.123.123", &u) >= 0);
        assert_se(sd_netlink_message_append_in_addr(message, IFA_LOCAL, &u.in) >= 0);
        assert_se(in_addr_from_string(AF_INET, "10.123.255.255", &u) >= 0);
        assert_se(sd_netlink_message_append_in_addr(message, IFA_BROADCAST, &u.in) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Add IPv6 addresses */
        assert_se(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6) >= 0);
        assert_se(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_addr_set_prefixlen(message, 64) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:0:123::123", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        assert_se(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6) >= 0);
        assert_se(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_addr_set_prefixlen(message, 64) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 default gateway (RTA_GATEWAY) */
        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET, "10.123.0.1", &u) >= 0);
        assert_se(sd_netlink_message_append_in_addr(message, RTA_GATEWAY, &u.in) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Add an IPv4 default gateway (RTA_VIA) */
        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:0:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_data(message, RTA_VIA,
                                                 &(RouteVia) {
                                                         .family = AF_INET6,
                                                         .address = u,
                                                 }, sizeof(RouteVia)) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        r = sd_netlink_call(rtnl, message, 0, NULL);
        if (r == -EINVAL)
                log_debug_errno(r, "RTA_VIA is not supported, ignoring: %m");
        else
                assert_se(r >= 0);
        support_rta_via = r >= 0;
        message = sd_netlink_message_unref(message);

        /* Add an IPv6 default gateway */
        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
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
        assert_se(sd_rtnl_message_new_addr_update(rtnl, &message, ifindex, AF_INET6) >= 0);
        assert_se(sd_rtnl_message_addr_set_scope(message, RT_SCOPE_UNIVERSE) >= 0);
        assert_se(sd_rtnl_message_addr_set_prefixlen(message, 64) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::124", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, IFA_LOCAL, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, IFA_FLAGS, IFA_F_NODAD) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Replace the previous IPv6 default gateway with one with preferred source address. */
        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_DELROUTE, AF_INET6, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Check again. */
        check_local_outbounds(rtnl, ifindex, 0, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET6, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_UNSPEC, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET, "2001:db8:1:123::123");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET6, "2001:db8:1:123::123");

        /* Replace the preferred source address. */
        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_DELROUTE, AF_INET6, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::123", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        assert_se(sd_rtnl_message_new_route(rtnl, &message, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC) >= 0);
        assert_se(sd_rtnl_message_route_set_type(message, RTN_UNICAST) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_PRIORITY, 1234) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_TABLE, RT_TABLE_MAIN) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::1", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_GATEWAY, &u.in6) >= 0);
        assert_se(sd_netlink_message_append_u32(message, RTA_OIF, ifindex) >= 0);
        assert_se(in_addr_from_string(AF_INET6, "2001:db8:1:123::124", &u) >= 0);
        assert_se(sd_netlink_message_append_in6_addr(message, RTA_PREFSRC, &u.in6) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);

        /* Check again. */
        check_local_outbounds(rtnl, ifindex, 0, AF_UNSPEC, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, 0, AF_INET6, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_UNSPEC, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET, "2001:db8:1:123::124");
        check_local_outbounds(rtnl, ifindex, ifindex, AF_INET6, "2001:db8:1:123::124");

        /* Cleanup */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_DELLINK, ifindex) >= 0);
        assert_se(sd_netlink_call(rtnl, message, 0, NULL) >= 0);
        message = sd_netlink_message_unref(message);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
