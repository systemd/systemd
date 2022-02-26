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

static int dhcp4_request_address_and_routes(Link *link, bool announce);

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
}

static int dhcp4_remove_address_and_routes(Link *link, bool only_marked) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);

        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP4)
                        continue;
                if (only_marked && !route_is_marked(route))
                        continue;

                k = route_remove(route);
                if (k < 0)
                        r = k;

                route_cancel_request(route, link);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP4)
                        continue;
                if (only_marked && !address_is_marked(address))
                        continue;

                k = address_remove(address);
                if (k < 0)
                        r = k;

                address_cancel_request(address);
        }

        return r;
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

static int dhcp4_retry(Link *link) {
        int r;

        assert(link);

        r = dhcp4_remove_address_and_routes(link, /* only_marked = */ false);
        if (r < 0)
                return r;

        r = link_request_static_nexthops(link, true);
        if (r < 0)
                return r;

        r = link_request_static_routes(link, true);
        if (r < 0)
                return r;

        return dhcp4_request_address_and_routes(link, false);
}

static int dhcp4_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp4_messages > 0);

        link->dhcp4_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r == -ENETUNREACH && !link->dhcp4_route_retrying) {

                /* It seems kernel does not support that the prefix route cannot be configured with
                 * route table. Let's once drop the config and reconfigure them later. */

                log_link_message_debug_errno(link, m, r, "Could not set DHCPv4 route, retrying later");
                link->dhcp4_route_failed = true;
                link->manager->dhcp4_prefix_root_cannot_set_table = true;
        } else if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set DHCPv4 route");
                link_enter_failed(link);
                return 1;
        }

        if (link->dhcp4_messages == 0 && link->dhcp4_route_failed) {
                link->dhcp4_route_failed = false;
                link->dhcp4_route_retrying = true;

                r = dhcp4_retry(link);
                if (r < 0)
                        link_enter_failed(link);

                return 1;
        }

        r = dhcp4_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp4_request_route(Route *in, Link *link) {
        _cleanup_(route_freep) Route *route = in;
        struct in_addr server;
        Route *existing;
        int r;

        assert(route);
        assert(link);
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
        if (route->mtu == 0)
                route->mtu = link->network->dhcp_route_mtu;

        if (route_get(NULL, link, route, &existing) < 0) /* This is a new route. */
                link->dhcp4_configured = false;
        else
                route_unmark(existing);

        return link_request_route(link, TAKE_PTR(route), true, &link->dhcp4_messages,
                                  dhcp4_route_handler, NULL);
}

static bool link_prefixroute(Link *link) {
        return !link->network->dhcp_route_table_set ||
                link->network->dhcp_route_table == RT_TABLE_MAIN ||
                link->manager->dhcp4_prefix_root_cannot_set_table;
}

static int dhcp4_request_prefix_route(Link *link) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr address, netmask;
        int r;

        assert(link);
        assert(link->dhcp_lease);

        if (link_prefixroute(link))
                /* When true, the route will be created by kernel. See dhcp4_update_address(). */
                return 0;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->dst.in.s_addr = address.s_addr & netmask.s_addr;
        route->dst_prefixlen = in4_addr_netmask_to_prefixlen(&netmask);
        route->prefsrc.in = address;
        route->scope = RT_SCOPE_LINK;

        return dhcp4_request_route(TAKE_PTR(route), link);
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

        return dhcp4_request_route(TAKE_PTR(route), link);
}

static int dhcp4_request_route_auto(
                Route *in,
                Link *link,
                const struct in_addr *gw) {

        _cleanup_(route_freep) Route *route = in;
        struct in_addr address, netmask, prefix;
        uint8_t prefixlen;
        int r;

        assert(route);
        assert(link);
        assert(link->dhcp_lease);
        assert(gw);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
        if (r < 0)
                return r;

        prefix.s_addr = address.s_addr & netmask.s_addr;
        prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

        if (in4_addr_is_localhost(&route->dst.in)) {
                if (in4_addr_is_set(gw))
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is localhost, "
                                       "ignoring gateway address "IPV4_ADDRESS_FMT_STR,
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen, IPV4_ADDRESS_FMT_VAL(*gw));

                route->scope = RT_SCOPE_HOST;
                route->gw_family = AF_UNSPEC;
                route->gw = IN_ADDR_NULL;
                route->prefsrc = IN_ADDR_NULL;

        } else if (in4_addr_equal(&route->dst.in, &address)) {
                if (in4_addr_is_set(gw))
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is equivalent to the acquired address, "
                                       "ignoring gateway address "IPV4_ADDRESS_FMT_STR,
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen, IPV4_ADDRESS_FMT_VAL(*gw));

                route->scope = RT_SCOPE_HOST;
                route->gw_family = AF_UNSPEC;
                route->gw = IN_ADDR_NULL;
                route->prefsrc.in = address;

        } else if (route->dst_prefixlen >= prefixlen &&
                   (route->dst.in.s_addr & netmask.s_addr) == prefix.s_addr) {
                if (in4_addr_is_set(gw))
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is in the assigned network "
                                       IPV4_ADDRESS_FMT_STR"/%u, ignoring gateway address "IPV4_ADDRESS_FMT_STR,
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen,
                                       IPV4_ADDRESS_FMT_VAL(prefix), prefixlen,
                                       IPV4_ADDRESS_FMT_VAL(*gw));

                route->scope = RT_SCOPE_LINK;
                route->gw_family = AF_UNSPEC;
                route->gw = IN_ADDR_NULL;
                route->prefsrc.in = address;

        } else {
                if (in4_addr_is_null(gw)) {
                        log_link_debug(link, "DHCP: requested route destination "IPV4_ADDRESS_FMT_STR"/%u is not in the assigned network "
                                       IPV4_ADDRESS_FMT_STR"/%u, but no gateway is specified, ignoring.",
                                       IPV4_ADDRESS_FMT_VAL(route->dst.in), route->dst_prefixlen,
                                       IPV4_ADDRESS_FMT_VAL(prefix), prefixlen);
                        return 0;
                }

                r = dhcp4_request_route_to_gateway(link, gw);
                if (r < 0)
                        return r;

                route->scope = RT_SCOPE_UNIVERSE;
                route->gw_family = AF_INET;
                route->gw.in = *gw;
                route->prefsrc.in = address;
        }

        return dhcp4_request_route(TAKE_PTR(route), link);
}

static int dhcp4_request_static_routes(Link *link, struct in_addr *ret_default_gw) {
        _cleanup_free_ sd_dhcp_route **static_routes = NULL, **classless_routes = NULL;
        size_t n_static_routes, n_classless_routes, n;
        struct in_addr default_gw = {};
        sd_dhcp_route **routes;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(ret_default_gw);

        r = sd_dhcp_lease_get_static_routes(link->dhcp_lease, &static_routes);
        if (r == -ENODATA)
                n_static_routes = 0;
        else if (r < 0)
                return r;
        else
                n_static_routes = r;

        r = sd_dhcp_lease_get_classless_routes(link->dhcp_lease, &classless_routes);
        if (r == -ENODATA)
                n_classless_routes = 0;
        else if (r < 0)
                return r;
        else
                n_classless_routes = r;

        if (n_classless_routes == 0 && n_static_routes == 0) {
                log_link_debug(link, "DHCP: No static routes received from DHCP server.");
                return 0;
        }

        /* if the DHCP server returns both a Classless Static Routes option and a Static Routes option,
         * the DHCP client MUST ignore the Static Routes option. */
        if (n_classless_routes > 0 && n_static_routes > 0)
                log_link_debug(link, "Classless static routes received from DHCP server: ignoring static-route option");

        if (!link->network->dhcp_use_routes) {

                /* Even if UseRoutes=no, try to find default gateway to make semi-static routes and
                 * routes to DNS or NTP servers can be configured in later steps. */

                for (size_t i = 0; i < n_classless_routes; i++) {
                        struct in_addr dst;
                        uint8_t prefixlen;

                        r = sd_dhcp_route_get_destination(classless_routes[i], &dst);
                        if (r < 0)
                                return r;

                        if (in4_addr_is_set(&dst))
                                continue;

                        r = sd_dhcp_route_get_destination_prefix_length(classless_routes[i], &prefixlen);
                        if (r < 0)
                                return r;

                        if (prefixlen != 0)
                                continue;

                        r = sd_dhcp_route_get_gateway(classless_routes[i], ret_default_gw);
                        if (r < 0)
                                return r;

                        break;
                }

                /* Do not return 1 here, to ensure the router option can override the default gateway
                 * that was found. */
                return 0;
        }

        if (n_classless_routes > 0) {
                n = n_classless_routes;
                routes = classless_routes;
        } else if (n_static_routes > 0){
                n = n_static_routes;
                routes = static_routes;
        } else
                assert_not_reached();

        for (size_t i = 0; i < n; i++) {
                _cleanup_(route_freep) Route *route = NULL;
                struct in_addr gw;

                r = route_new(&route);
                if (r < 0)
                        return r;

                route->gw_family = AF_INET;

                r = sd_dhcp_route_get_gateway(routes[i], &gw);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination(routes[i], &route->dst.in);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination_prefix_length(routes[i], &route->dst_prefixlen);
                if (r < 0)
                        return r;

                /* When classless static routes are provided, then router option will be ignored. To
                 * use the default gateway later in other routes, e.g., routes to dns servers, here we
                 * need to find the default gateway in the classless static routes. */
                if (n_classless_routes > 0 &&
                    in4_addr_is_null(&route->dst.in) && route->dst_prefixlen == 0 &&
                    in4_addr_is_null(&default_gw))
                        default_gw = gw;

                r = dhcp4_request_route_auto(TAKE_PTR(route), link, &gw);
                if (r < 0)
                        return r;
        }

        *ret_default_gw = default_gw;
        return n_classless_routes > 0;
}

static int dhcp4_request_gateway(Link *link, struct in_addr *gw) {
        _cleanup_(route_freep) Route *route = NULL;
        const struct in_addr *router;
        struct in_addr address;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(gw);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_router(link->dhcp_lease, &router);
        if (IN_SET(r, 0, -ENODATA)) {
                log_link_debug(link, "DHCP: No gateway received from DHCP server.");
                return 0;
        }
        if (r < 0)
                return r;
        if (in4_addr_is_null(&router[0])) {
                log_link_debug(link, "DHCP: Received gateway address is null.");
                return 0;
        }

        if (!link->network->dhcp_use_gateway) {
                /* When no classless static route is provided, even if UseGateway=no, use the gateway
                 * address to configure semi-static routes or routes to DNS or NTP servers. Note, if
                 * neither UseRoutes= nor UseGateway= is disabled, use the default gateway in classless
                 * static routes if provided (in that case, in4_addr_is_null(gw) below is true). */
                if (in4_addr_is_null(gw))
                        *gw = router[0];
                return 0;
        }

        /* The dhcp netmask may mask out the gateway. First, add an explicit route for the gateway host
         * so that we can route no matter the netmask or existing kernel route tables. */
        r = dhcp4_request_route_to_gateway(link, &router[0]);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        /* Next, add a default gateway. */
        route->gw_family = AF_INET;
        route->gw.in = router[0];
        route->prefsrc.in = address;

        r = dhcp4_request_route(TAKE_PTR(route), link);
        if (r < 0)
                return r;

        /* When no classless static route is provided, or UseRoutes=no, then use the router address to
         * configure semi-static routes and routes to DNS or NTP servers in later steps. */
        *gw = router[0];
        return 0;
}

static int dhcp4_request_semi_static_routes(Link *link, const struct in_addr *gw) {
        Route *rt;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(gw);

        if (in4_addr_is_null(gw))
                return 0;

        HASHMAP_FOREACH(rt, link->network->routes_by_section) {
                _cleanup_(route_freep) Route *route = NULL;

                if (!rt->gateway_from_dhcp_or_ra)
                        continue;

                if (rt->gw_family != AF_INET)
                        continue;

                r = dhcp4_request_route_to_gateway(link, gw);
                if (r < 0)
                        return r;

                r = route_dup(rt, &route);
                if (r < 0)
                        return r;

                route->gw.in = *gw;

                r = dhcp4_request_route(TAKE_PTR(route), link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_request_routes_to_servers(
                Link *link,
                const struct in_addr *servers,
                size_t n_servers,
                const struct in_addr *gw) {

        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(servers || n_servers == 0);
        assert(gw);

        for (size_t i = 0; i < n_servers; i++) {
                _cleanup_(route_freep) Route *route = NULL;

                if (in4_addr_is_null(&servers[i]))
                        continue;

                r = route_new(&route);
                if (r < 0)
                        return r;

                route->dst.in = servers[i];
                route->dst_prefixlen = 32;

                r = dhcp4_request_route_auto(TAKE_PTR(route), link, gw);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_request_routes_to_dns(Link *link, const struct in_addr *gw) {
        const struct in_addr *dns;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(gw);

        if (!link->network->dhcp_use_dns ||
            !link->network->dhcp_routes_to_dns)
                return 0;

        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
        if (IN_SET(r, 0, -ENODATA))
                return 0;
        if (r < 0)
                return r;

        return dhcp4_request_routes_to_servers(link, dns, r, gw);
}

static int dhcp4_request_routes_to_ntp(Link *link, const struct in_addr *gw) {
        const struct in_addr *ntp;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(gw);

        if (!link->network->dhcp_use_ntp ||
            !link->network->dhcp_routes_to_ntp)
                return 0;

        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &ntp);
        if (IN_SET(r, 0, -ENODATA))
                return 0;
        if (r < 0)
                return r;

        return dhcp4_request_routes_to_servers(link, ntp, r, gw);
}

static int dhcp4_request_routes(Link *link) {
        struct in_addr gw = {};
        int r;

        assert(link);
        assert(link->dhcp_lease);

        r = dhcp4_request_prefix_route(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request prefix route: %m");

        r = dhcp4_request_static_routes(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request static routes: %m");
        if (r == 0) {
                /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
                 * a Router option, the DHCP client MUST ignore the Router option. */
                r = dhcp4_request_gateway(link, &gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP error: Could not request gateway: %m");
        }

        r = dhcp4_request_semi_static_routes(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes with Gateway=_dhcp4 setting: %m");

        r = dhcp4_request_routes_to_dns(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes to DNS servers: %m");

        r = dhcp4_request_routes_to_ntp(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not request routes to NTP servers: %m");

        return 0;
}

static int dhcp_reset_mtu(Link *link) {
        uint16_t mtu;
        int r;

        assert(link);

        if (!link->network->dhcp_use_mtu)
                return 0;

        r = sd_dhcp_lease_get_mtu(link->dhcp_lease, &mtu);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: failed to get MTU from lease: %m");

        if (link->original_mtu == mtu)
                return 0;

        r = link_request_to_set_mtu(link, link->original_mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: could not reset MTU: %m");

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
        int k, r = 0;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        log_link_info(link, "DHCP lease lost");

        link->dhcp4_configured = false;

        if (link->network->dhcp_use_6rd &&
            dhcp4_lease_has_pd_prefix(link->dhcp_lease))
                dhcp4_pd_prefix_lost(link);

        k = dhcp4_remove_address_and_routes(link, /* only_marked = */ false);
        if (k < 0)
                r = k;

        k = dhcp_reset_mtu(link);
        if (k < 0)
                r = k;

        k = dhcp_reset_hostname(link);
        if (k < 0)
                r = k;

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

static int dhcp4_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp4_messages > 0);

        link->dhcp4_messages--;

        r = address_configure_handler_internal(rtnl, m, link, "Could not set DHCPv4 address");
        if (r <= 0)
                return r;

        r = dhcp4_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp4_request_address(Link *link, bool announce) {
        _cleanup_(address_freep) Address *addr = NULL;
        struct in_addr address, netmask, server;
        unsigned prefixlen;
        Address *existing;
        usec_t lifetime_usec;
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp_lease);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no address: %m");

        r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no netmask: %m");

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &server);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCP error: failed to get DHCP server IP address: %m");

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                uint32_t lifetime_sec;

                r = sd_dhcp_lease_get_lifetime(link->dhcp_lease, &lifetime_sec);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP error: no lifetime: %m");

                lifetime_usec = usec_add(lifetime_sec * USEC_PER_SEC, now(clock_boottime_or_monotonic()));
        } else
                lifetime_usec = USEC_INFINITY;

        prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

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
        address_set_broadcast(addr, link);
        SET_FLAG(addr->flags, IFA_F_NOPREFIXROUTE, !link_prefixroute(link));
        addr->route_metric = link->network->dhcp_route_metric;
        addr->duplicate_address_detection = link->network->dhcp_send_decline ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_NO;

        r = free_and_strdup_warn(&addr->label, link->network->dhcp_label);
        if (r < 0)
                return r;

        if (address_get(link, addr, &existing) < 0) /* The address is new. */
                link->dhcp4_configured = false;
        else
                address_unmark(existing);

        r = link_request_address(link, TAKE_PTR(addr), true, &link->dhcp4_messages,
                                 dhcp4_address_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request DHCPv4 address: %m");

        return 0;
}

static int dhcp4_request_address_and_routes(Link *link, bool announce) {
        int r;

        assert(link);

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP4, NULL);
        link_mark_routes(link, NETWORK_CONFIG_SOURCE_DHCP4, NULL);

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
                if (dhcp4_lease_has_pd_prefix(link->dhcp_lease)) {
                        r = dhcp4_pd_prefix_acquired(link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to process 6rd option: %m");
                } else if (dhcp4_lease_has_pd_prefix(old_lease))
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
            dhcp4_lease_has_pd_prefix(link->dhcp_lease)) {
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
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        switch (event) {
                case SD_DHCP_CLIENT_EVENT_STOP:
                        if (link->ipv4ll) {
                                log_link_debug(link, "DHCP client is stopped. Acquiring IPv4 link-local address");

                                r = sd_ipv4ll_start(link->ipv4ll);
                                if (r < 0)
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

                if (duid->type == DUID_TYPE_LLT && duid->raw_data_len == 0)
                        r = sd_dhcp_client_set_iaid_duid_llt(link->dhcp_client,
                                                             link->network->dhcp_iaid_set,
                                                             link->network->dhcp_iaid,
                                                             duid->llt_time);
                else
                        r = sd_dhcp_client_set_iaid_duid(link->dhcp_client,
                                                         link->network->dhcp_iaid_set,
                                                         link->network->dhcp_iaid,
                                                         duid->type,
                                                         duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                         duid->raw_data_len);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set IAID+DUID: %m");
                break;
        }
        case DHCP_CLIENT_ID_DUID_ONLY: {
                /* If configured, apply user specified DUID */
                const DUID *duid = link_get_dhcp4_duid(link);

                if (duid->type == DUID_TYPE_LLT && duid->raw_data_len == 0)
                        r = sd_dhcp_client_set_duid_llt(link->dhcp_client,
                                                        duid->llt_time);
                else
                        r = sd_dhcp_client_set_duid(link->dhcp_client,
                                                    duid->type,
                                                    duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                    duid->raw_data_len);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set DUID: %m");
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

static int dhcp4_set_request_address(Link *link) {
        Address *a;

        assert(link);
        assert(link->network);
        assert(link->dhcp_client);

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                return 0;

        SET_FOREACH(a, link->addresses) {
                if (a->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;
                if (a->family != AF_INET)
                        continue;
                if (link_address_is_dynamic(link, a))
                        break;
        }

        if (!a)
                return 0;

        log_link_debug(link, "DHCPv4 CLIENT: requesting " IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(a->in_addr.in));

        return sd_dhcp_client_set_request_address(link->dhcp_client, &a->in_addr.in);
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
        if (r < 0 && link->sd_device && sd_device_get_property_value(link->sd_device, "ID_NET_DHCP_BROADCAST", &val) >= 0) {
                r = parse_boolean(val);
                if (r < 0)
                        log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to parse ID_NET_DHCP_BROADCAST, ignoring: %m");
                else
                        log_link_debug(link, "DHCPv4 CLIENT: Detected ID_NET_DHCP_BROADCAST='%d'.", r);

        }
        return r == true;
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

        if (link->mtu > 0) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set MTU: %m");
        }

        if (!link->network->dhcp_anonymize) {
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

        if (link->network->dhcp_fallback_lease_lifetime > 0) {
                r = sd_dhcp_client_set_fallback_lease_lifetime(link->dhcp_client, link->network->dhcp_fallback_lease_lifetime);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed set to lease lifetime: %m");
        }

        r = dhcp4_set_request_address(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv4 CLIENT: Failed to set initial DHCPv4 address: %m");

        return dhcp4_set_client_identifier(link);
}

int dhcp4_update_mac(Link *link) {
        int r;

        assert(link);

        if (!link->dhcp_client)
                return 0;

        r = sd_dhcp_client_set_mac(link->dhcp_client, link->hw_addr.bytes,
                                   link->bcast_addr.length > 0 ? link->bcast_addr.bytes : NULL,
                                   link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        return dhcp4_set_client_identifier(link);
}

int dhcp4_start(Link *link) {
        int r;

        assert(link);

        if (!link->dhcp_client)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp_client_is_running(link->dhcp_client) > 0)
                return 0;

        r = sd_dhcp_client_start(link->dhcp_client);
        if (r < 0)
                return r;

        return 1;
}

static int dhcp4_configure_duid(Link *link) {
        assert(link);

        if (!IN_SET(link->network->dhcp_client_identifier, DHCP_CLIENT_ID_DUID, DHCP_CLIENT_ID_DUID_ONLY))
                return 1;

        return dhcp_configure_duid(link, link_get_dhcp4_duid(link));
}

int dhcp4_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (!IN_SET(link->hw_addr.length, ETH_ALEN, INFINIBAND_ALEN) ||
            hw_addr_is_null(&link->hw_addr))
                /* No MAC address is assigned to the hardware, or non-supported MAC address length. */
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

        r = link_queue_request(link, REQUEST_TYPE_DHCP4_CLIENT, NULL, false, NULL, NULL, NULL);
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

        Network *network = data;
        uint64_t a;
        int r;

        assert(network);
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

        int *tos = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

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
                network->dhcp_fallback_lease_lifetime = 0;
                return 0;
        }

        /* We accept only "forever" or "infinity". */
        if (!STR_IN_SET(rvalue, "forever", "infinity")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid LeaseLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        network->dhcp_fallback_lease_lifetime = UINT32_MAX;

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

        char **label = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

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
        [DHCP_CLIENT_ID_MAC] = "mac",
        [DHCP_CLIENT_ID_DUID] = "duid",
        [DHCP_CLIENT_ID_DUID_ONLY] = "duid-only",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_client_identifier, DHCPClientIdentifier);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DHCPClientIdentifier,
                         "Failed to parse client identifier type");
