/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "alloc-util.h"
#include "dhcp-client-internal.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "parse-util.h"
#include "network-internal.h"
#include "networkd-address.h"
#include "networkd-dhcp-prefix-delegation.h"
#include "networkd-dhcp4-bus.h"
#include "networkd-dhcp4.h"
#include "networkd-ipv4acd.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-setlink.h"
#include "networkd-state-file.h"
#include "string-table.h"
#include "strv.h"
#include "sysctl-util.h"

void network_adjust_dhcp4(Network *network) {
        assert(network);

        if (!FLAGS_SET(network->dhcp, ADDRESS_FAMILY_IPV4))
                return;

        if (network->dhcp_use_gateway < 0)
                network->dhcp_use_gateway = network->dhcp_use_routes;

        /* RFC7844 section 3.: MAY contain the Client Identifier option
         * Section 3.5: clients MUST use client identifiers based solely on the link-layer address
         * NOTE: Using MAC, as it does not reveal extra information, and some servers might not answer
         * if this option is not sent */
        if (network->dhcp_anonymize &&
            network->dhcp_client_identifier >= 0 &&
            network->dhcp_client_identifier != DHCP_CLIENT_ID_MAC) {
                log_warning("%s: ClientIdentifier= is set, although Anonymize=yes. Using ClientIdentifier=mac.",
                            network->filename);
                network->dhcp_client_identifier = DHCP_CLIENT_ID_MAC;
        }

        if (network->dhcp_client_identifier < 0)
                network->dhcp_client_identifier = network->dhcp_anonymize ? DHCP_CLIENT_ID_MAC : DHCP_CLIENT_ID_DUID;

        /* By default, RapidCommit= is enabled when Anonymize=no and neither AllowList= nor DenyList= is specified. */
        if (network->dhcp_use_rapid_commit < 0)
                network->dhcp_use_rapid_commit =
                        !network->dhcp_anonymize &&
                        set_isempty(network->dhcp_allow_listed_ip) &&
                        set_isempty(network->dhcp_deny_listed_ip);
}

static int dhcp4_prefix_covers(
                Link *link,
                const struct in_addr *in_prefix,
                uint8_t in_prefixlen) {

        struct in_addr prefix;
        uint8_t prefixlen;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(in_prefix);

        /* Return true if the input address or address range is in the assigned network.
         * E.g. if the DHCP server provides 192.168.0.100/24, then this returns true for the address or
         * address range in 192.168.0.0/24, and returns false otherwise. */

        r = sd_dhcp_lease_get_prefix(link->dhcp_lease, &prefix, &prefixlen);
        if (r < 0)
                return r;

        return in4_addr_prefix_covers_full(&prefix, prefixlen, in_prefix, in_prefixlen);
}

static int dhcp4_get_router(Link *link, struct in_addr *ret) {
        const struct in_addr *routers;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(ret);

        r = sd_dhcp_lease_get_router(link->dhcp_lease, &routers);
        if (r < 0)
                return r;

        /* The router option may provide multiple routers, We only use the first non-null address. */

        FOREACH_ARRAY(router, routers, r) {
                if (in4_addr_is_null(router))
                        continue;

                *ret = *router;
                return 0;
        }

        return -ENODATA;
}

static int dhcp4_get_classless_static_or_static_routes(Link *link, sd_dhcp_route ***ret_routes, size_t *ret_num) {
        _cleanup_free_ sd_dhcp_route **routes = NULL;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        /* If the DHCP server returns both a Classless Static Routes option and a Static Routes option,
         * the DHCP client MUST ignore the Static Routes option. */

        r = sd_dhcp_lease_get_classless_routes(link->dhcp_lease, &routes);
        if (r >= 0) {
                assert(r > 0);
                if (ret_routes)
                        *ret_routes = TAKE_PTR(routes);
                if (ret_num)
                        *ret_num = r;
                return 1; /* classless */
        } else if (r != -ENODATA)
                return r;

        r = sd_dhcp_lease_get_static_routes(link->dhcp_lease, &routes);
        if (r < 0)
                return r;

        assert(r > 0);
        if (ret_routes)
                *ret_routes = TAKE_PTR(routes);
        if (ret_num)
                *ret_num = r;
        return 0; /* static */
}

static int dhcp4_find_gateway_for_destination(
                Link *link,
                const struct in_addr *destination,
                uint8_t prefixlength,
                bool allow_null,
                struct in_addr *ret) {

        _cleanup_free_ sd_dhcp_route **routes = NULL;
        size_t n_routes = 0;
        bool is_classless, reachable;
        uint8_t max_prefixlen = UINT8_MAX;
        struct in_addr gw;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(destination);
        assert(ret);

        /* This tries to find the most suitable gateway for an address or address range.
         * E.g. if the server provides the default gateway 192.168.0.1 and a classless static route for
         * 8.0.0.0/8 with gateway 192.168.0.2, then this returns 192.168.0.2 for 8.8.8.8/32, and 192.168.0.1
         * for 9.9.9.9/32. If 'allow_null' flag is set, and the input address or address range is in the
         * assigned network, then the default gateway will be ignored and the null address will be returned
         * unless a matching non-default gateway found. */

        r = dhcp4_prefix_covers(link, destination, prefixlength);
        if (r < 0)
                return r;
        reachable = r > 0;

        r = dhcp4_get_classless_static_or_static_routes(link, &routes, &n_routes);
        if (r < 0 && r != -ENODATA)
                return r;
        is_classless = r > 0;

        /* First, find most suitable gateway. */
        FOREACH_ARRAY(e, routes, n_routes) {
                struct in_addr dst;
                uint8_t len;

                r = sd_dhcp_route_get_destination(*e, &dst);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination_prefix_length(*e, &len);
                if (r < 0)
                        return r;

                r = in4_addr_prefix_covers_full(&dst, len, destination, prefixlength);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (max_prefixlen != UINT8_MAX && max_prefixlen > len)
                        continue;

                r = sd_dhcp_route_get_gateway(*e, &gw);
                if (r < 0)
                        return r;

                max_prefixlen = len;
        }

        /* Found a suitable gateway in classless static routes or static routes. */
        if (max_prefixlen != UINT8_MAX) {
                if (max_prefixlen == 0 && reachable && allow_null)
                        /* Do not return the default gateway, if the destination is in the assigned network. */
                        *ret = (struct in_addr) {};
                else
                        *ret = gw;
                return 0;
        }

        /* When the destination is in the assigned network, return the null address if allowed. */
        if (reachable && allow_null) {
                *ret = (struct in_addr) {};
                return 0;
        }

        /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
         * a Router option, the DHCP client MUST ignore the Router option. */
        if (!is_classless) {
                r = dhcp4_get_router(link, ret);
                if (r >= 0)
                        return 0;
                if (r != -ENODATA)
                        return r;
        }

        if (!reachable)
                return -EHOSTUNREACH; /* Not in the same network, cannot reach the destination. */

        assert(!allow_null);
        return -ENODATA; /* No matching gateway found. */
}

static int dhcp4_remove_address_and_routes(Link *link, bool only_marked) {
        Address *address;
        Route *route;
        int ret = 0;

        assert(link);
        assert(link->manager);

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP4)
                        continue;
                if (route->nexthop.ifindex != 0 && route->nexthop.ifindex != link->ifindex)
                        continue;
                if (only_marked && !route_is_marked(route))
                        continue;

                RET_GATHER(ret, route_remove(route));
                route_cancel_request(route, link);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP4)
                        continue;
                if (only_marked && !address_is_marked(address))
                        continue;

                RET_GATHER(ret, address_remove_and_cancel(address, link));
        }

        return ret;
}

static int dhcp4_address_get(Link *link, Address **ret) {
        Address *address;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP4)
                        continue;
                if (address_is_marked(address))
                        continue;

                if (ret)
                        *ret = address;
                return 0;
        }

        return -ENOENT;
}

static int dhcp4_address_ready_callback(Address *address) {
        assert(address);
        assert(address->link);

        /* Do not call this again. */
        address->callback = NULL;

        return dhcp4_check_ready(address->link);
}

int dhcp4_check_ready(Link *link) {
        Address *address;
        int r;

        assert(link);

        if (link->dhcp4_messages > 0) {
                log_link_debug(link, "%s(): DHCPv4 address and routes are not set.", __func__);
                return 0;
        }

        if (dhcp4_address_get(link, &address) < 0) {
                log_link_debug(link, "%s(): DHCPv4 address is not set.", __func__);
                return 0;
        }

        if (!address_is_ready(address)) {
                log_link_debug(link, "%s(): DHCPv4 address is not ready.", __func__);
                address->callback = dhcp4_address_ready_callback;
                return 0;
        }

        link->dhcp4_configured = true;
        log_link_debug(link, "DHCPv4 address and routes set.");

        /* New address and routes are configured now. Let's release old lease. */
        r = dhcp4_remove_address_and_routes(link, /* only_marked = */ true);
        if (r < 0)
                return r;

        r = sd_ipv4ll_stop(link->ipv4ll);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to drop IPv4 link-local address: %m");

        link_check_ready(link);
        return 0;
}

static int dhcp4_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(m);
        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, route, "Could not set DHCPv4 route");
        if (r <= 0)
                return r;

        r = dhcp4_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp4_request_route(Route *route, Link *link) {
        struct in_addr server;
        Route *existing;
        int r;

        assert(route);
        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(link->dhcp_lease);

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &server);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to get DHCP server IP address: %m");

        route->source = NETWORK_CONFIG_SOURCE_DHCP4;
        route->provider.in = server;
        route->family = AF_INET;
        if (!route->protocol_set)
                route->protocol = RTPROT_DHCP;
        if (!route->priority_set)
                route->priority = link->network->dhcp_route_metric;
        if (!route->table_set)
                route->table = link_get_dhcp4_route_table(link);
        r = route_metric_set(&route->metric, RTAX_MTU, link->network->dhcp_route_mtu);
        if (r < 0)
                return r;
        r = route_metric_set(&route->metric, RTAX_INITCWND, link->network->dhcp_initial_congestion_window);
        if (r < 0)
                return r;
        r = route_metric_set(&route->metric, RTAX_INITRWND, link->network->dhcp_advertised_receive_window);
        if (r < 0)
                return r;
        r = route_metric_set(&route->metric, RTAX_QUICKACK, link->network->dhcp_quickack);
        if (r < 0)
                return r;

        if (route_get(link->manager, route, &existing) < 0) /* This is a new route. */
                link->dhcp4_configured = false;
        else
                route_unmark(existing);

        return link_request_route(link, route, &link->dhcp4_messages, dhcp4_route_handler, NULL);
}

static bool link_prefixroute(Link *link) {
        return !link->network->dhcp_route_table_set ||
                link->network->dhcp_route_table == RT_TABLE_MAIN;
}

static int dhcp4_request_prefix_route(Link *link) {
        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        if (link_prefixroute(link))
                /* When true, the route will be created by kernel. See dhcp4_update_address(). */
                return 0;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->scope = RT_SCOPE_LINK;

        r = sd_dhcp_lease_get_prefix(link->dhcp_lease, &route->dst.in, &route->dst_prefixlen);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &route->prefsrc.in);
        if (r < 0)
                return r;

        return dhcp4_request_route(route, link);
}

static int dhcp4_request_route_to_gateway(Link *link, const struct in_addr *gw) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr address;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(gw);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->dst.in = *gw;
        route->dst_prefixlen = 32;
        route->prefsrc.in = address;
        route->scope = RT_SCOPE_LINK;

        return dhcp4_request_route(route, link);
}

static int dhcp4_request_route_auto(
                Route *route,
                Link *link,
                const struct in_addr *gw) {

        struct in_addr address;
        int r;

        assert(route);
        assert(link);
        assert(link->dhcp_lease);
        assert(gw);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        if (in4_addr_is_localhost(&route->dst.in)) {
                if (in4_addr_is_set(gw))
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is localhost, "
                                       "ignoring gateway address "IPV4_ADDRESS_FMT_STR,
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen, IPV4_ADDRESS_FMT_VAL(*gw));

                route->scope = RT_SCOPE_HOST;
                route->nexthop.family = AF_UNSPEC;
                route->nexthop.gw = IN_ADDR_NULL;
                route->prefsrc = IN_ADDR_NULL;

        } else if (in4_addr_equal(&route->dst.in, &address)) {
                if (in4_addr_is_set(gw))
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is equivalent to the acquired address, "
                                       "ignoring gateway address "IPV4_ADDRESS_FMT_STR,
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen, IPV4_ADDRESS_FMT_VAL(*gw));

                route->scope = RT_SCOPE_HOST;
                route->nexthop.family = AF_UNSPEC;
                route->nexthop.gw = IN_ADDR_NULL;
                route->prefsrc.in = address;

        } else if (in4_addr_is_null(gw)) {
                r = dhcp4_prefix_covers(link, &route->dst.in, route->dst_prefixlen);
                if (r < 0)
                        return r;
                if (r == 0 && DEBUG_LOGGING) {
                        struct in_addr prefix;
                        uint8_t prefixlen;

                        r = sd_dhcp_lease_get_prefix(link->dhcp_lease, &prefix, &prefixlen);
                        if (r < 0)
                                return r;

                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is not in the assigned network "
                                       IPV4_ADDRESS_FMT_STR"/%u, but no gateway is specified, using 'link' scope.",
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen,
                                       IPV4_ADDRESS_FMT_VAL(prefix), prefixlen);
                }

                route->scope = RT_SCOPE_LINK;
                route->nexthop.family = AF_UNSPEC;
                route->nexthop.gw = IN_ADDR_NULL;
                route->prefsrc.in = address;

        } else {
                r = dhcp4_request_route_to_gateway(link, gw);
                if (r < 0)
                        return r;

                route->scope = RT_SCOPE_UNIVERSE;
                route->nexthop.family = AF_INET;
                route->nexthop.gw.in = *gw;
                route->prefsrc.in = address;
        }

        return dhcp4_request_route(route, link);
}

static int dhcp4_request_classless_static_or_static_routes(Link *link) {
        _cleanup_free_ sd_dhcp_route **routes = NULL;
        size_t n_routes;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        if (!link->network->dhcp_use_routes)
                return 0;

        r = dhcp4_get_classless_static_or_static_routes(link, &routes, &n_routes);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        FOREACH_ARRAY(e, routes, n_routes) {
                _cleanup_(route_freep) Route *route = NULL;
                struct in_addr gw;

                r = route_new(&route);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_gateway(*e, &gw);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination(*e, &route->dst.in);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination_prefix_length(*e, &route->dst_prefixlen);
                if (r < 0)
                        return r;

                r = dhcp4_request_route_auto(route, link, &gw);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_request_default_gateway(Link *link) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr address, router;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        if (!link->network->dhcp_use_gateway)
                return 0;

        /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
         * a Router option, the DHCP client MUST ignore the Router option. */
        if (link->network->dhcp_use_routes &&
            dhcp4_get_classless_static_or_static_routes(link, NULL, NULL) > 0)
                return 0;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        r = dhcp4_get_router(link, &router);
        if (r == -ENODATA) {
                log_link_debug(link, "DHCP: No valid router address received from DHCP server.");
                return 0;
        }
        if (r < 0)
                return r;

        /* The dhcp netmask may mask out the gateway. First, add an explicit route for the gateway host
         * so that we can route no matter the netmask or existing kernel route tables. */
        r = dhcp4_request_route_to_gateway(link, &router);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        /* Next, add a default gateway. */
        route->nexthop.family = AF_INET;
        route->nexthop.gw.in = router;
        route->prefsrc.in = address;

        return dhcp4_request_route(route, link);
}

static int dhcp4_request_semi_static_routes(Link *link) {
        Route *rt;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        HASHMAP_FOREACH(rt, link->network->routes_by_section) {
                _cleanup_(route_freep) Route *route = NULL;
                struct in_addr gw;

                if (!rt->gateway_from_dhcp_or_ra)
                        continue;

                if (rt->nexthop.family != AF_INET)
                        continue;

                assert(rt->family == AF_INET);

                r = dhcp4_find_gateway_for_destination(link, &rt->dst.in, rt->dst_prefixlen, /* allow_null = */ false, &gw);
                if (IN_SET(r, -EHOSTUNREACH, -ENODATA)) {
                        log_link_debug_errno(link, r, "DHCP: Cannot find suitable gateway for destination %s of semi-static route, ignoring: %m",
                                             IN4_ADDR_PREFIX_TO_STRING(&rt->dst.in, rt->dst_prefixlen));
                        continue;
                }
                if (r < 0)
                        return r;

                r = dhcp4_request_route_to_gateway(link, &gw);
                if (r < 0)
                        return r;

                r = route_dup(rt, NULL, &route);
                if (r < 0)
                        return r;

                route->nexthop.gw.in = gw;

                r = dhcp4_request_route(route, link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_request_routes_to_servers(
                Link *link,
                const struct in_addr *servers,
                size_t n_servers) {

        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(servers || n_servers == 0);

        FOREACH_ARRAY(dst, servers, n_servers) {
                _cleanup_(route_freep) Route *route = NULL;
                struct in_addr gw;

                if (in4_addr_is_null(dst))
                        continue;

                r = dhcp4_find_gateway_for_destination(link, dst, 32, /* allow_null = */ true, &gw);
                if (r == -EHOSTUNREACH) {
                        log_link_debug_errno(link, r, "DHCP: Cannot find suitable gateway for destination %s, ignoring: %m",
                                             IN4_ADDR_PREFIX_TO_STRING(dst, 32));
                        continue;
                }
                if (r < 0)
                        return r;

                r = route_new(&route);
                if (r < 0)
                        return r;

                route->dst.in = *dst;
                route->dst_prefixlen = 32;

                r = dhcp4_request_route_auto(route, link, &gw);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_request_routes_to_dns(Link *link) {
        const struct in_addr *dns;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        if (!link->network->dhcp_use_dns ||
            !link->network->dhcp_routes_to_dns)
                return 0;

        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
        if (IN_SET(r, 0, -ENODATA))
                return 0;
        if (r < 0)
                return r;

        return dhcp4_request_routes_to_servers(link, dns, r);
}

static int dhcp4_request_routes_to_ntp(Link *link) {
        const struct in_addr *ntp;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        if (!link->network->dhcp_use_ntp ||
            !link->network->dhcp_routes_to_ntp)
                return 0;

        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &ntp);
        if (IN_SET(r, 0, -ENODATA))
                return 0;
        if (r < 0)
                return r;

        return dhcp4_request_routes_to_servers(link, ntp, r);
}

static int dhcp4_request_routes(Link *link) {
        int r;

        assert(link);
        assert(link->dhcp_lease);

        r = dhcp4_request_prefix_route(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request prefix route: %m");

        r = dhcp4_request_default_gateway(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request default gateway: %m");

        r = dhcp4_request_classless_static_or_static_routes(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request static routes: %m");

        r = dhcp4_request_semi_static_routes(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes with Gateway=_dhcp4 setting: %m");

        r = dhcp4_request_routes_to_dns(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes to DNS servers: %m");

        r = dhcp4_request_routes_to_ntp(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes to NTP servers: %m");

        return 0;
}

static int dhcp_reset_mtu(Link *link) {
        int r;

        assert(link);

        if (!link->network->dhcp_use_mtu)
                return 0;

        r = link_request_to_set_mtu(link, link->original_mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not queue request to reset MTU: %m");

        return 0;
}

static int dhcp_reset_hostname(Link *link) {
        const char *hostname;
        int r;

        assert(link);

        if (!link->network->dhcp_use_hostname)
                return 0;

        hostname = link->network->dhcp_hostname;
        if (!hostname)
                (void) sd_dhcp_lease_get_hostname(link->dhcp_lease, &hostname);

        if (!hostname)
                return 0;

        /* If a hostname was set due to the lease, then unset it now. */
        r = manager_set_hostname(link->manager, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Failed to reset transient hostname: %m");

        return 0;
}

int dhcp4_lease_lost(Link *link) {
        int r = 0;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        log_link_info(link, "DHCP lease lost");

        link->dhcp4_configured = false;

        if (link->network->dhcp_use_6rd &&
            sd_dhcp_lease_has_6rd(link->dhcp_lease))
                dhcp4_pd_prefix_lost(link);

        RET_GATHER(r, dhcp4_remove_address_and_routes(link, /* only_marked = */ false));
        RET_GATHER(r, dhcp_reset_mtu(link));
        RET_GATHER(r, dhcp_reset_hostname(link));

        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);
        link_dirty(link);

        /* If one of the above failed. Do not request nexthops and routes. */
        if (r < 0)
                return r;

        r = link_request_static_nexthops(link, true);
        if (r < 0)
                return r;

        return link_request_static_routes(link, true);
}

static int dhcp4_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

        r = address_configure_handler_internal(rtnl, m, link, "Could not set DHCPv4 address");
        if (r <= 0)
                return r;

        r = dhcp4_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp4_request_address(Link *link, bool announce) {
        _cleanup_(address_unrefp) Address *addr = NULL;
        struct in_addr address, server;
        uint8_t prefixlen;
        Address *existing;
        usec_t lifetime_usec;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(link->dhcp_lease);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no address: %m");

        r = sd_dhcp_lease_get_prefix(link->dhcp_lease, NULL, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no netmask: %m");

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &server);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCP error: failed to get DHCP server IP address: %m");

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                r = sd_dhcp_lease_get_lifetime_timestamp(link->dhcp_lease, CLOCK_BOOTTIME, &lifetime_usec);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP error: failed to get lifetime: %m");
        } else
                lifetime_usec = USEC_INFINITY;

        if (announce) {
                const struct in_addr *router;

                r = sd_dhcp_lease_get_router(link->dhcp_lease, &router);
                if (r < 0 && r != -ENODATA)
                        return log_link_error_errno(link, r, "DHCP error: Could not get gateway: %m");

                if (r > 0 && in4_addr_is_set(&router[0]))
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address "IPV4_ADDRESS_FMT_STR"/%u, gateway "IPV4_ADDRESS_FMT_STR" acquired from "IPV4_ADDRESS_FMT_STR,
                                                    IPV4_ADDRESS_FMT_VAL(address),
                                                    prefixlen,
                                                    IPV4_ADDRESS_FMT_VAL(router[0]),
                                                    IPV4_ADDRESS_FMT_VAL(server)),
                                   "ADDRESS="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address),
                                   "PREFIXLEN=%u", prefixlen,
                                   "GATEWAY="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(router[0]));
                else
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address "IPV4_ADDRESS_FMT_STR"/%u acquired from "IPV4_ADDRESS_FMT_STR,
                                                    IPV4_ADDRESS_FMT_VAL(address),
                                                    prefixlen,
                                                    IPV4_ADDRESS_FMT_VAL(server)),
                                   "ADDRESS="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address),
                                   "PREFIXLEN=%u", prefixlen);
        }

        r = address_new(&addr);
        if (r < 0)
                return log_oom();

        addr->source = NETWORK_CONFIG_SOURCE_DHCP4;
        addr->provider.in = server;
        addr->family = AF_INET;
        addr->in_addr.in.s_addr = address.s_addr;
        addr->lifetime_preferred_usec = lifetime_usec;
        addr->lifetime_valid_usec = lifetime_usec;
        addr->prefixlen = prefixlen;
        r = sd_dhcp_lease_get_broadcast(link->dhcp_lease, &addr->broadcast);
        if (r < 0 && r != -ENODATA)
                return log_link_warning_errno(link, r, "DHCP: failed to get broadcast address: %m");
        SET_FLAG(addr->flags, IFA_F_NOPREFIXROUTE, !link_prefixroute(link));
        addr->route_metric = link->network->dhcp_route_metric;
        addr->duplicate_address_detection = link->network->dhcp_send_decline ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_NO;

        r = free_and_strdup_warn(&addr->label, link->network->dhcp_label);
        if (r < 0)
                return r;

        r = free_and_strdup_warn(&addr->netlabel, link->network->dhcp_netlabel);
        if (r < 0)
                return r;

        if (address_get(link, addr, &existing) < 0) /* The address is new. */
                link->dhcp4_configured = false;
        else
                address_unmark(existing);

        r = link_request_address(link, addr, &link->dhcp4_messages,
                                 dhcp4_address_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request DHCPv4 address: %m");

        return 0;
}

static int dhcp4_request_address_and_routes(Link *link, bool announce) {
        int r;

        assert(link);

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP4);
        manager_mark_routes(link->manager, link, NETWORK_CONFIG_SOURCE_DHCP4);

        r = dhcp4_request_address(link, announce);
        if (r < 0)
                return r;

        r = dhcp4_request_routes(link);
        if (r < 0)
                return r;

        if (!link->dhcp4_configured) {
                link_set_state(link, LINK_STATE_CONFIGURING);
                link_check_ready(link);
        }

        return 0;
}

static int dhcp_lease_renew(sd_dhcp_client *client, Link *link) {
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *old_lease = NULL;
        sd_dhcp_lease *lease;
        int r;

        assert(link);
        assert(link->network);
        assert(client);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no lease: %m");

        old_lease = TAKE_PTR(link->dhcp_lease);
        link->dhcp_lease = sd_dhcp_lease_ref(lease);
        link_dirty(link);

        if (link->network->dhcp_use_6rd) {
                if (sd_dhcp_lease_has_6rd(link->dhcp_lease)) {
                        r = dhcp4_pd_prefix_acquired(link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to process 6rd option: %m");
                } else if (sd_dhcp_lease_has_6rd(old_lease))
                        dhcp4_pd_prefix_lost(link);
        }

        return dhcp4_request_address_and_routes(link, false);
}

static int dhcp_lease_acquired(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        int r;

        assert(client);
        assert(link);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: No lease: %m");

        sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp_lease = sd_dhcp_lease_ref(lease);
        link_dirty(link);

        if (link->network->dhcp_use_mtu) {
                uint16_t mtu;

                r = sd_dhcp_lease_get_mtu(lease, &mtu);
                if (r >= 0) {
                        r = link_request_to_set_mtu(link, mtu);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set MTU to %" PRIu16 ": %m", mtu);
                }
        }

        if (link->network->dhcp_use_hostname) {
                const char *dhcpname = NULL;
                _cleanup_free_ char *hostname = NULL;

                if (link->network->dhcp_hostname)
                        dhcpname = link->network->dhcp_hostname;
                else
                        (void) sd_dhcp_lease_get_hostname(lease, &dhcpname);

                if (dhcpname) {
                        r = shorten_overlong(dhcpname, &hostname);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Unable to shorten overlong DHCP hostname '%s', ignoring: %m", dhcpname);
                        if (r == 1)
                                log_link_notice(link, "Overlong DHCP hostname received, shortened from '%s' to '%s'", dhcpname, hostname);
                }

                if (hostname) {
                        r = manager_set_hostname(link->manager, hostname);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set transient hostname to '%s': %m", hostname);
                }
        }

        if (link->network->dhcp_use_timezone) {
                const char *tz = NULL;

                (void) sd_dhcp_lease_get_timezone(link->dhcp_lease, &tz);

                if (tz) {
                        r = manager_set_timezone(link->manager, tz);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set timezone to '%s': %m", tz);
                }
        }

        if (link->network->dhcp_use_6rd &&
            sd_dhcp_lease_has_6rd(link->dhcp_lease)) {
                r = dhcp4_pd_prefix_acquired(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to process 6rd option: %m");
        }

        return dhcp4_request_address_and_routes(link, true);
}

static int dhcp_lease_ip_change(sd_dhcp_client *client, Link *link) {
        int r;

        r = dhcp_lease_acquired(client, link);
        if (r < 0)
                (void) dhcp4_lease_lost(link);

        return r;
}

static int dhcp_server_is_filtered(Link *link, sd_dhcp_client *client) {
        sd_dhcp_lease *lease;
        struct in_addr addr;
        int r;

        assert(link);
        assert(link->network);
        assert(client);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DHCP lease: %m");

        r = sd_dhcp_lease_get_server_identifier(lease, &addr);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to get DHCP server IP address: %m");

        if (in4_address_is_filtered(&addr, link->network->dhcp_allow_listed_ip, link->network->dhcp_deny_listed_ip)) {
                if (DEBUG_LOGGING) {
                        if (link->network->dhcp_allow_listed_ip)
                                log_link_debug(link, "DHCPv4 server IP address "IPV4_ADDRESS_FMT_STR" not found in allow-list, ignoring offer.",
                                               IPV4_ADDRESS_FMT_VAL(addr));
                        else
                                log_link_debug(link, "DHCPv4 server IP address "IPV4_ADDRESS_FMT_STR" found in deny-list, ignoring offer.",
                                               IPV4_ADDRESS_FMT_VAL(addr));
                }

                return true;
        }

        return false;
}

static int dhcp4_handler(sd_dhcp_client *client, int event, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        int r;

        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        switch (event) {
                case SD_DHCP_CLIENT_EVENT_STOP:
                        if (link->ipv4ll) {
                                log_link_debug(link, "DHCP client is stopped. Acquiring IPv4 link-local address");

                                if (in4_addr_is_set(&link->network->ipv4ll_start_address)) {
                                        r = sd_ipv4ll_set_address(link->ipv4ll, &link->network->ipv4ll_start_address);
                                        if (r < 0)
                                                return log_link_warning_errno(link, r, "Could not set IPv4 link-local start address: %m");
                                }

                                r = sd_ipv4ll_start(link->ipv4ll);
                                if (r < 0 && r != -ESTALE) /* On exit, we cannot and should not start sd-ipv4ll. */
                                        return log_link_warning_errno(link, r, "Could not acquire IPv4 link-local address: %m");
                        }

                        if (FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                                log_link_notice(link, "DHCPv4 connection considered critical, ignoring request to reconfigure it.");
                                return 0;
                        }

                        if (link->dhcp_lease) {
                                if (link->network->dhcp_send_release) {
                                        r = sd_dhcp_client_send_release(client);
                                        if (r < 0)
                                                log_link_full_errno(link,
                                                                    ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_WARNING,
                                                                    r, "Failed to send DHCP RELEASE, ignoring: %m");
                                }

                                r = dhcp4_lease_lost(link);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return r;
                                }
                        }

                        break;
                case SD_DHCP_CLIENT_EVENT_EXPIRED:
                        if (FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                                log_link_notice(link, "DHCPv4 connection considered critical, ignoring request to reconfigure it.");
                                return 0;
                        }

                        if (link->dhcp_lease) {
                                r = dhcp4_lease_lost(link);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return r;
                                }
                        }

                        break;
                case SD_DHCP_CLIENT_EVENT_IP_CHANGE:
                        if (FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                                log_link_notice(link, "DHCPv4 connection considered critical, ignoring request to reconfigure it.");
                                return 0;
                        }

                        r = dhcp_lease_ip_change(client, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }

                        break;
                case SD_DHCP_CLIENT_EVENT_RENEW:
                        r = dhcp_lease_renew(client, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                        break;
                case SD_DHCP_CLIENT_EVENT_IP_ACQUIRE:
                        r = dhcp_lease_acquired(client, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                        break;
                case SD_DHCP_CLIENT_EVENT_SELECTING:
                        r = dhcp_server_is_filtered(link, client);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                        if (r > 0)
                                return -ENOMSG;
                        break;

                case SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE:
                        if (link->ipv4ll && !sd_ipv4ll_is_running(link->ipv4ll)) {
                                log_link_debug(link, "Problems acquiring DHCP lease, acquiring IPv4 link-local address");

                                if (in4_addr_is_set(&link->network->ipv4ll_start_address)) {
                                        r = sd_ipv4ll_set_address(link->ipv4ll, &link->network->ipv4ll_start_address);
                                        if (r < 0)
                                                return log_link_warning_errno(link, r, "Could not set IPv4 link-local start address: %m");
                                }

                                r = sd_ipv4ll_start(link->ipv4ll);
                                if (r < 0)
                                        return log_link_warning_errno(link, r, "Could not acquire IPv4 link-local address: %m");
                        }
                        break;

                default:
                        if (event < 0)
                                log_link_warning_errno(link, event, "DHCP error: Client failed: %m");
                        else
                                log_link_warning(link, "DHCP unknown event: %i", event);
                        break;
        }

        return 0;
}

static int dhcp4_set_hostname(Link *link) {
        _cleanup_free_ char *hostname = NULL;
        const char *hn;
        int r;

        assert(link);

        if (!link->network->dhcp_send_hostname)
                hn = NULL;
        else if (link->network->dhcp_hostname)
                hn = link->network->dhcp_hostname;
        else {
                r = gethostname_strict(&hostname);
                if (r < 0 && r != -ENXIO) /* ENXIO: no hostname set or hostname is "localhost" */
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to get hostname: %m");

                hn = hostname;
        }

        r = sd_dhcp_client_set_hostname(link->dhcp_client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set hostname: %m");

        return 0;
}

static int dhcp4_set_client_identifier(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp_client);

        switch (link->network->dhcp_client_identifier) {
        case DHCP_CLIENT_ID_DUID: {
                /* If configured, apply user specified DUID and IAID */
                const DUID *duid = link_get_dhcp4_duid(link);

                if (duid->raw_data_len == 0)
                        switch (duid->type) {
                        case DUID_TYPE_LLT:
                                r = sd_dhcp_client_set_iaid_duid_llt(link->dhcp_client,
                                                                     link->network->dhcp_iaid_set,
                                                                     link->network->dhcp_iaid,
                                                                     duid->llt_time);
                                break;
                        case DUID_TYPE_LL:
                                r = sd_dhcp_client_set_iaid_duid_ll(link->dhcp_client,
                                                                    link->network->dhcp_iaid_set,
                                                                    link->network->dhcp_iaid);
                                break;
                        case DUID_TYPE_EN:
                                r = sd_dhcp_client_set_iaid_duid_en(link->dhcp_client,
                                                                    link->network->dhcp_iaid_set,
                                                                    link->network->dhcp_iaid);
                                break;
                        case DUID_TYPE_UUID:
                                r = sd_dhcp_client_set_iaid_duid_uuid(link->dhcp_client,
                                                                      link->network->dhcp_iaid_set,
                                                                      link->network->dhcp_iaid);
                                break;
                        default:
                                r = sd_dhcp_client_set_iaid_duid_raw(link->dhcp_client,
                                                                     link->network->dhcp_iaid_set,
                                                                     link->network->dhcp_iaid,
                                                                     duid->type, NULL, 0);
                        }
                else
                        r = sd_dhcp_client_set_iaid_duid_raw(link->dhcp_client,
                                                             link->network->dhcp_iaid_set,
                                                             link->network->dhcp_iaid,
                                                             duid->type, duid->raw_data, duid->raw_data_len);
                if (r < 0)
                        return r;
                break;
        }
        case DHCP_CLIENT_ID_MAC: {
                const uint8_t *hw_addr = link->hw_addr.bytes;
                size_t hw_addr_len = link->hw_addr.length;

                if (link->iftype == ARPHRD_INFINIBAND && hw_addr_len == INFINIBAND_ALEN) {
                        /* set_client_id expects only last 8 bytes of an IB address */
                        hw_addr += INFINIBAND_ALEN - 8;
                        hw_addr_len -= INFINIBAND_ALEN - 8;
                }

                r = sd_dhcp_client_set_client_id(link->dhcp_client,
                                                 link->iftype,
                                                 hw_addr,
                                                 hw_addr_len);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set client ID: %m");
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int dhcp4_find_dynamic_address(Link *link, struct in_addr *ret) {
        Address *a;

        assert(link);
        assert(link->network);
        assert(ret);

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                return false;

        SET_FOREACH(a, link->addresses) {
                if (a->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;
                if (a->family != AF_INET)
                        continue;
                if (link_address_is_dynamic(link, a))
                        break;
        }

        if (!a)
                return false;

        *ret = a->in_addr.in;
        return true;
}

static int dhcp4_set_request_address(Link *link) {
        struct in_addr a;

        assert(link);
        assert(link->network);
        assert(link->dhcp_client);

        a = link->network->dhcp_request_address;

        if (in4_addr_is_null(&a))
                (void) dhcp4_find_dynamic_address(link, &a);

        if (in4_addr_is_null(&a))
                return 0;

        log_link_debug(link, "DHCPv4 CLIENT: requesting %s.", IN4_ADDR_TO_STRING(&a));
        return sd_dhcp_client_set_request_address(link->dhcp_client, &a);
}

static bool link_needs_dhcp_broadcast(Link *link) {
        const char *val;
        int r;

        assert(link);
        assert(link->network);

        /* Return the setting in DHCP[4].RequestBroadcast if specified. Otherwise return the device property
         * ID_NET_DHCP_BROADCAST setting, which may be set for interfaces requiring that the DHCPOFFER message
         * is being broadcast because they can't  handle unicast messages while not fully configured.
         * If neither is set or a failure occurs, return false, which is the default for this flag.
         */
        r = link->network->dhcp_broadcast;
        if (r < 0 && link->dev && sd_device_get_property_value(link->dev, "ID_NET_DHCP_BROADCAST", &val) >= 0) {
                r = parse_boolean(val);
                if (r < 0)
                        log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to parse ID_NET_DHCP_BROADCAST, ignoring: %m");
                else
                        log_link_debug(link, "DHCPv4 CLIENT: Detected ID_NET_DHCP_BROADCAST='%d'.", r);

        }
        return r == true;
}

static bool link_dhcp4_ipv6_only_mode(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->dhcp_ipv6_only_mode >= 0)
                return link->network->dhcp_ipv6_only_mode;

        return link_dhcp6_enabled(link) || link_ipv6_accept_ra_enabled(link);
}

static int dhcp4_configure(Link *link) {
        sd_dhcp_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp_client)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EBUSY), "DHCPv4 client is already configured.");

        r = sd_dhcp_client_new(&link->dhcp_client, link->network->dhcp_anonymize);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to allocate DHCPv4 client: %m");

        r = sd_dhcp_client_attach_event(link->dhcp_client, link->manager->event, 0);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to attach event to DHCPv4 client: %m");

        r = sd_dhcp_client_attach_device(link->dhcp_client, link->dev);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to attach device: %m");

        r = sd_dhcp_client_set_rapid_commit(link->dhcp_client, link->network->dhcp_use_rapid_commit);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set rapid commit: %m");

        r = sd_dhcp_client_set_mac(link->dhcp_client,
                                   link->hw_addr.bytes,
                                   link->bcast_addr.length > 0 ? link->bcast_addr.bytes : NULL,
                                   link->hw_addr.length, link->iftype);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set MAC address: %m");

        r = sd_dhcp_client_set_ifindex(link->dhcp_client, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set ifindex: %m");

        r = sd_dhcp_client_set_callback(link->dhcp_client, dhcp4_handler, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set callback: %m");

        r = sd_dhcp_client_set_request_broadcast(link->dhcp_client, link_needs_dhcp_broadcast(link));
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for broadcast: %m");

        r = dhcp_client_set_state_callback(link->dhcp_client, dhcp_client_callback_bus, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set state change callback: %m");

        if (link->mtu > 0) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set MTU: %m");
        }

        if (!link->network->dhcp_anonymize) {
                r = dhcp4_set_request_address(link);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set initial DHCPv4 address: %m");

                if (link->network->dhcp_use_mtu) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_MTU_INTERFACE);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for MTU: %m");
                }

                if (link->network->dhcp_use_routes) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_STATIC_ROUTE);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for static route: %m");

                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for classless static route: %m");
                }

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_DOMAIN_SEARCH);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for domain search list: %m");
                }

                if (link->network->dhcp_use_ntp) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NTP_SERVER);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for NTP server: %m");
                }

                if (link->network->dhcp_use_sip) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_SIP_SERVER);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for SIP server: %m");
                }
                if (link->network->dhcp_use_captive_portal) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for captive portal: %m");
                }

                if (link->network->dhcp_use_timezone) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_TZDB_TIMEZONE);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for timezone: %m");
                }

                if (link->network->dhcp_use_6rd) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_6RD);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for 6rd: %m");
                }

                if (link_dhcp4_ipv6_only_mode(link)) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for IPv6-only preferred option: %m");
                }

                SET_FOREACH(request_options, link->network->dhcp_request_options) {
                        uint32_t option = PTR_TO_UINT32(request_options);

                        r = sd_dhcp_client_set_request_option(link->dhcp_client, option);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set request flag for '%u': %m", option);
                }

                ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_options) {
                        r = sd_dhcp_client_add_option(link->dhcp_client, send_option);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set send option: %m");
                }

                ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_vendor_options) {
                        r = sd_dhcp_client_add_vendor_option(link->dhcp_client, send_option);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set send option: %m");
                }

                r = dhcp4_set_hostname(link);
                if (r < 0)
                        return r;

                if (link->network->dhcp_vendor_class_identifier) {
                        r = sd_dhcp_client_set_vendor_class_identifier(link->dhcp_client,
                                                                       link->network->dhcp_vendor_class_identifier);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set vendor class identifier: %m");
                }

                if (link->network->dhcp_mudurl) {
                        r = sd_dhcp_client_set_mud_url(link->dhcp_client, link->network->dhcp_mudurl);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set MUD URL: %m");
                }

                if (link->network->dhcp_user_class) {
                        r = sd_dhcp_client_set_user_class(link->dhcp_client, link->network->dhcp_user_class);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set user class: %m");
                }
        }

        if (link->network->dhcp_client_port > 0) {
                r = sd_dhcp_client_set_client_port(link->dhcp_client, link->network->dhcp_client_port);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set listen port: %m");
        }

        if (link->network->dhcp_max_attempts > 0) {
                r = sd_dhcp_client_set_max_attempts(link->dhcp_client, link->network->dhcp_max_attempts);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set max attempts: %m");
        }

        if (link->network->dhcp_ip_service_type >= 0) {
                r = sd_dhcp_client_set_service_type(link->dhcp_client, link->network->dhcp_ip_service_type);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set IP service type: %m");
        }

        if (link->network->dhcp_socket_priority_set) {
                r = sd_dhcp_client_set_socket_priority(link->dhcp_client, link->network->dhcp_socket_priority);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set socket priority: %m");
        }

        if (link->network->dhcp_fallback_lease_lifetime_usec > 0) {
                r = sd_dhcp_client_set_fallback_lease_lifetime(link->dhcp_client, link->network->dhcp_fallback_lease_lifetime_usec);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed set to lease lifetime: %m");
        }

        return dhcp4_set_client_identifier(link);
}

int dhcp4_update_mac(Link *link) {
        bool restart;
        int r;

        assert(link);

        if (!link->dhcp_client)
                return 0;

        restart = sd_dhcp_client_is_running(link->dhcp_client);

        r = sd_dhcp_client_stop(link->dhcp_client);
        if (r < 0)
                return r;

        r = sd_dhcp_client_set_mac(link->dhcp_client,
                                   link->hw_addr.bytes,
                                   link->bcast_addr.length > 0 ? link->bcast_addr.bytes : NULL,
                                   link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        r = dhcp4_set_client_identifier(link);
        if (r < 0)
                return r;

        if (restart) {
                r = dhcp4_start(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dhcp4_update_ipv6_connectivity(Link *link) {
        assert(link);

        if (!link->network)
                return 0;

        if (!link->network->dhcp_ipv6_only_mode)
                return 0;

        if (!link->dhcp_client)
                return 0;

        /* If the client is running, set the current connectivity. */
        if (sd_dhcp_client_is_running(link->dhcp_client))
                return sd_dhcp_client_set_ipv6_connectivity(link->dhcp_client, link_has_ipv6_connectivity(link));

        /* If the client has been already stopped or not started yet, let's check the current connectivity
         * and start the client if necessary. */
        if (link_has_ipv6_connectivity(link))
                return 0;

        return dhcp4_start_full(link, /* set_ipv6_connectivity = */ false);
}

int dhcp4_start_full(Link *link, bool set_ipv6_connectivity) {
        int r;

        assert(link);
        assert(link->network);

        if (!link->dhcp_client)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp_client_is_running(link->dhcp_client) > 0)
                return 0;

        r = sd_dhcp_client_start(link->dhcp_client);
        if (r < 0)
                return r;

        if (set_ipv6_connectivity) {
                r = dhcp4_update_ipv6_connectivity(link);
                if (r < 0)
                        return r;
        }

        return 1;
}

int dhcp4_renew(Link *link) {
        assert(link);

        if (!link->dhcp_client)
                return 0;

        /* The DHCPv4 client may have been stopped by the IPv6 only mode. Let's unconditionally restart the
         * client if it is not running. */
        if (!sd_dhcp_client_is_running(link->dhcp_client))
                return dhcp4_start(link);

        /* The client may be waiting for IPv6 connectivity. Let's restart the client in that case. */
        if (dhcp_client_get_state(link->dhcp_client) != DHCP_STATE_BOUND)
                return sd_dhcp_client_interrupt_ipv6_only_mode(link->dhcp_client);

        /* Otherwise, send a RENEW command. */
        return sd_dhcp_client_send_renew(link->dhcp_client);
}

static int dhcp4_configure_duid(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->dhcp_client_identifier != DHCP_CLIENT_ID_DUID)
                return 1;

        return dhcp_configure_duid(link, link_get_dhcp4_duid(link));
}

static int dhcp4_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return 0;

        r = dhcp4_configure_duid(link);
        if (r <= 0)
                return r;

        r = dhcp4_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCPv4 client: %m");

        r = dhcp4_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start DHCPv4 client: %m");

        log_link_debug(link, "DHCPv4 client is configured%s.",
                       r > 0 ? ", acquiring DHCPv4 lease" : "");
        return 1;
}

int link_request_dhcp4_client(Link *link) {
        int r;

        assert(link);

        if (!link_dhcp4_enabled(link))
                return 0;

        if (link->dhcp_client)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_DHCP4_CLIENT, dhcp4_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the DHCPv4 client: %m");

        log_link_debug(link, "Requested configuring of the DHCPv4 client.");
        return 0;
}

int config_parse_dhcp_max_attempts(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(data);
        uint64_t a;
        int r;

        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp_max_attempts = 0;
                return 0;
        }

        if (streq(rvalue, "infinity")) {
                network->dhcp_max_attempts = UINT64_MAX;
                return 0;
        }

        r = safe_atou64(rvalue, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse DHCP maximum attempts, ignoring: %s", rvalue);
                return 0;
        }

        if (a == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= must be positive integer or 'infinity', ignoring: %s", lvalue, rvalue);
                return 0;
        }

        network->dhcp_max_attempts = a;

        return 0;
}

int config_parse_dhcp_ip_service_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *tos = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                *tos = -1; /* use sd_dhcp_client's default (currently, CS6). */
        else if (streq(rvalue, "none"))
                *tos = 0;
        else if (streq(rvalue, "CS4"))
                *tos = IPTOS_CLASS_CS4;
        else if (streq(rvalue, "CS6"))
                *tos = IPTOS_CLASS_CS6;
        else
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);

        return 0;
}

int config_parse_dhcp_socket_priority(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(data);
        int a, r;

        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp_socket_priority_set = false;
                return 0;
        }

        r = safe_atoi(rvalue, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse socket priority, ignoring: %s", rvalue);
                return 0;
        }

        network->dhcp_socket_priority_set = true;
        network->dhcp_socket_priority = a;

        return 0;
}

int config_parse_dhcp_fallback_lease_lifetime(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->dhcp_fallback_lease_lifetime_usec = 0;
                return 0;
        }

        /* We accept only "forever" or "infinity". */
        if (!STR_IN_SET(rvalue, "forever", "infinity")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid LeaseLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        network->dhcp_fallback_lease_lifetime_usec = USEC_INFINITY;

        return 0;
}

int config_parse_dhcp_label(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **label = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *label = mfree(*label);
                return 0;
        }

        if (!address_label_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Address label is too long or invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(label, rvalue);
}

static const char* const dhcp_client_identifier_table[_DHCP_CLIENT_ID_MAX] = {
        [DHCP_CLIENT_ID_MAC]  = "mac",
        [DHCP_CLIENT_ID_DUID] = "duid",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_client_identifier, DHCPClientIdentifier);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DHCPClientIdentifier,
                         "Failed to parse client identifier type");
