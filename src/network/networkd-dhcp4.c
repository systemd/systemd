/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "escape.h"
#include "alloc-util.h"
#include "dhcp-client-internal.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "parse-util.h"
#include "network-internal.h"
#include "networkd-address.h"
#include "networkd-dhcp4.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-state-file.h"
#include "string-table.h"
#include "strv.h"
#include "sysctl-util.h"
#include "web-util.h"

static int dhcp4_update_address(Link *link, bool announce);
static int dhcp4_remove_all(Link *link);

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

static int dhcp4_release_old_lease(Link *link) {
        Route *route;
        int k, r = 0;

        assert(link);

        if (!link->dhcp_address_old && set_isempty(link->dhcp_routes_old))
                return 0;

        log_link_debug(link, "Removing old DHCPv4 address and routes.");

        SET_FOREACH(route, link->dhcp_routes_old) {
                k = route_remove(route, NULL, link, NULL);
                if (k < 0)
                        r = k;
        }

        if (link->dhcp_address_old) {
                k = address_remove(link->dhcp_address_old, link, NULL);
                if (k < 0)
                        r = k;
        }

        return r;
}

static void dhcp4_check_ready(Link *link) {
        int r;

        if (link->network->dhcp_send_decline && !link->dhcp4_address_bind)
                return;

        if (link->dhcp4_messages > 0)
                return;

        link->dhcp4_configured = true;

        /* New address and routes are configured now. Let's release old lease. */
        r = dhcp4_release_old_lease(link);
        if (r < 0) {
                link_enter_failed(link);
                return;
        }

        r = sd_ipv4ll_stop(link->ipv4ll);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to drop IPv4 link-local address, ignoring: %m");

        link_check_ready(link);
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

                r = dhcp4_remove_all(link);
                if (r < 0)
                        link_enter_failed(link);
                return 1;
        }

        dhcp4_check_ready(link);

        return 1;
}

static int dhcp_route_configure(Route *route, Link *link) {
        Route *ret;
        int r;

        assert(route);
        assert(link);

        r = route_configure(route, link, dhcp4_route_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set DHCPv4 route: %m");

        link->dhcp4_messages++;

        r = set_ensure_put(&link->dhcp_routes, &route_hash_ops, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv4 route: %m");

        (void) set_remove(link->dhcp_routes_old, ret);

        return 0;
}

static bool link_prefixroute(Link *link) {
        return !link->network->dhcp_route_table_set ||
                link->network->dhcp_route_table == RT_TABLE_MAIN ||
                link->manager->dhcp4_prefix_root_cannot_set_table;
}

static int link_set_dhcp_prefix_route(Link *link) {
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

        route->family = AF_INET;
        route->dst.in.s_addr = address.s_addr & netmask.s_addr;
        route->dst_prefixlen = in4_addr_netmask_to_prefixlen(&netmask);
        route->prefsrc.in = address;
        route->scope = RT_SCOPE_LINK;
        route->protocol = RTPROT_DHCP;
        route->table = link_get_dhcp_route_table(link);
        route->mtu = link->network->dhcp_route_mtu;

        return dhcp_route_configure(route, link);
}

static int link_set_dhcp_route_to_gateway(Link *link, const struct in_addr *gw) {
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

        route->family = AF_INET;
        route->dst.in = *gw;
        route->dst_prefixlen = 32;
        route->prefsrc.in = address;
        route->scope = RT_SCOPE_LINK;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_route_metric;
        route->table = link_get_dhcp_route_table(link);
        route->mtu = link->network->dhcp_route_mtu;

        return dhcp_route_configure(route, link);
}

static int dhcp_route_configure_auto(
                Route *route,
                Link *link,
                const struct in_addr *gw) {

        struct in_addr address, netmask, prefix;
        uint8_t prefixlen;
        int r;

        assert(route);
        assert(link);
        assert(link->dhcp_lease);
        assert(gw);

        /* The route object may be reused in an iteration. All elements must be set or cleared. */

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

                r = link_set_dhcp_route_to_gateway(link, gw);
                if (r < 0)
                        return r;

                route->scope = RT_SCOPE_UNIVERSE;
                route->gw_family = AF_INET;
                route->gw.in = *gw;
                route->prefsrc.in = address;
        }

        return dhcp_route_configure(route, link);
}

static int link_set_dhcp_static_routes(Link *link, struct in_addr *ret_default_gw) {
        _cleanup_free_ sd_dhcp_route **static_routes = NULL;
        bool classless_route = false, static_route = false;
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr default_gw = {};
        int n, r;

        assert(link);
        assert(link->dhcp_lease);
        assert(ret_default_gw);

        if (!link->network->dhcp_use_routes)
                return 0;

        n = sd_dhcp_lease_get_routes(link->dhcp_lease, &static_routes);
        if (IN_SET(n, 0, -ENODATA)) {
                log_link_debug(link, "DHCP: No static routes received from DHCP server.");
                return 0;
        }
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
                switch (sd_dhcp_route_get_option(static_routes[i])) {
                case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
                        classless_route = true;
                        break;
                case SD_DHCP_OPTION_STATIC_ROUTE:
                        static_route = true;
                        break;
                }
        }

        /* if the DHCP server returns both a Classless Static Routes option and a Static Routes option,
         * the DHCP client MUST ignore the Static Routes option. */
        if (classless_route && static_route)
                log_link_debug(link, "Classless static routes received from DHCP server: ignoring static-route option");

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->gw_family = AF_INET;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_route_metric;
        route->table = link_get_dhcp_route_table(link);
        route->mtu = link->network->dhcp_route_mtu;

        for (int i = 0; i < n; i++) {
                struct in_addr gw;

                if (sd_dhcp_route_get_option(static_routes[i]) !=
                    (classless_route ? SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE : SD_DHCP_OPTION_STATIC_ROUTE))
                        continue;

                r = sd_dhcp_route_get_gateway(static_routes[i], &gw);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination(static_routes[i], &route->dst.in);
                if (r < 0)
                        return r;

                r = sd_dhcp_route_get_destination_prefix_length(static_routes[i], &route->dst_prefixlen);
                if (r < 0)
                        return r;

                /* When classless static routes are provided, then router option will be ignored. To
                 * use the default gateway later in other routes, e.g., routes to dns servers, here we
                 * need to find the default gateway in the classless static routes. */
                if (classless_route &&
                    in4_addr_is_null(&route->dst.in) && route->dst_prefixlen == 0 &&
                    in4_addr_is_null(&default_gw))
                        default_gw = gw;

                r = dhcp_route_configure_auto(route, link, &gw);
                if (r < 0)
                        return r;
        }

        *ret_default_gw = default_gw;
        return classless_route;
}

static int link_set_dhcp_gateway(Link *link, struct in_addr *ret_gw) {
        _cleanup_(route_freep) Route *route = NULL;
        const struct in_addr *router;
        struct in_addr address;
        Route *rt;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(ret_gw);

        if (!link->network->dhcp_use_gateway)
                return 0;

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

        /* The dhcp netmask may mask out the gateway. First, add an explicit route for the gateway host
         * so that we can route no matter the netmask or existing kernel route tables. */
        r = link_set_dhcp_route_to_gateway(link, &router[0]);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        /* Next, add a default gateway. */
        route->family = AF_INET;
        route->gw_family = AF_INET;
        route->gw.in = router[0];
        route->prefsrc.in = address;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_route_metric;
        route->table = link_get_dhcp_route_table(link);
        route->mtu = link->network->dhcp_route_mtu;

        r = dhcp_route_configure(route, link);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(rt, link->network->routes_by_section) {
                if (!rt->gateway_from_dhcp_or_ra)
                        continue;

                if (rt->gw_family != AF_INET)
                        continue;

                rt->gw.in = router[0];
                if (!rt->protocol_set)
                        rt->protocol = RTPROT_DHCP;
                if (!rt->priority_set)
                        rt->priority = link->network->dhcp_route_metric;
                if (!rt->table_set)
                        rt->table = link_get_dhcp_route_table(link);
                if (rt->mtu == 0)
                        rt->mtu = link->network->dhcp_route_mtu;

                r = dhcp_route_configure(rt, link);
                if (r < 0)
                        return r;
        }

        *ret_gw = router[0];
        return 0;
}

static int link_set_routes_to_servers(
                Link *link,
                const struct in_addr *servers,
                size_t n_servers,
                const struct in_addr *gw) {

        _cleanup_(route_freep) Route *route = NULL;
        int r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);
        assert(servers || n_servers == 0);
        assert(gw);

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->dst_prefixlen = 32;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_route_metric;
        route->table = link_get_dhcp_route_table(link);
        route->mtu = link->network->dhcp_route_mtu;

        for (size_t i = 0; i < n_servers; i++) {
                if (in4_addr_is_null(&servers[i]))
                        continue;

                route->dst.in = servers[i];

                r = dhcp_route_configure_auto(route, link, gw);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_set_routes_to_dns(Link *link, const struct in_addr *gw) {
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

        return link_set_routes_to_servers(link, dns, r, gw);
}

static int link_set_routes_to_ntp(Link *link, const struct in_addr *gw) {
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

        return link_set_routes_to_servers(link, ntp, r, gw);
}

static int link_set_dhcp_routes(Link *link) {
        struct in_addr gw = {};
        Route *rt;
        int r;

        assert(link);

        if (!link->dhcp_lease) /* link went down while we configured the IP addresses? */
                return 0;

        if (!link->network) /* link went down while we configured the IP addresses? */
                return 0;

        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                /* During configuring addresses, the link lost its carrier. As networkd is dropping
                 * the addresses now, let's not configure the routes either. */
                return 0;

        while ((rt = set_steal_first(link->dhcp_routes))) {
                r = set_ensure_put(&link->dhcp_routes_old, &route_hash_ops, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store old DHCPv4 route: %m");
        }

        r = link_set_dhcp_prefix_route(link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not set prefix route: %m");

        r = link_set_dhcp_static_routes(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not set static routes: %m");
        if (r == 0) {
                /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
                 * a Router option, the DHCP client MUST ignore the Router option. */
                r = link_set_dhcp_gateway(link, &gw);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP error: Could not set gateway: %m");
        }

        r = link_set_routes_to_dns(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not set routes to DNS servers: %m");

        r = link_set_routes_to_ntp(link, &gw);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: Could not set routes to NTP servers: %m");

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

        r = link_set_mtu(link, link->original_mtu);
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

static int dhcp4_remove_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->dhcp4_remove_messages > 0);

        link->dhcp4_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -ESRCH)
                log_link_message_warning_errno(link, m, r, "Failed to remove DHCPv4 route, ignoring");

        if (link->dhcp4_remove_messages == 0) {
                r = dhcp4_update_address(link, false);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int dhcp4_remove_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->dhcp4_remove_messages > 0);

        link->dhcp4_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_link_message_warning_errno(link, m, r, "Failed to remove DHCPv4 address, ignoring");
        else
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->dhcp4_remove_messages == 0) {
                r = dhcp4_update_address(link, false);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int dhcp4_remove_all(Link *link) {
        Route *route;
        int k, r = 0;

        assert(link);

        SET_FOREACH(route, link->dhcp_routes) {
                k = route_remove(route, NULL, link, dhcp4_remove_route_handler);
                if (k < 0)
                        r = k;
                else
                        link->dhcp4_remove_messages++;
        }

        if (link->dhcp_address) {
                k = address_remove(link->dhcp_address, link, dhcp4_remove_address_handler);
                if (k < 0)
                        r = k;
                else
                        link->dhcp4_remove_messages++;
        }

        return r;
}

static int dhcp_lease_lost(Link *link) {
        int k, r = 0;

        assert(link);
        assert(link->dhcp_lease);

        log_link_info(link, "DHCP lease lost");

        link->dhcp4_configured = false;

        /* dhcp_lease_lost() may be called during renewing IP address. */
        k = dhcp4_release_old_lease(link);
        if (k < 0)
                r = k;

        k = dhcp4_remove_all(link);
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

        (void) sd_ipv4acd_stop(link->dhcp_acd);

        return r;
}

static void dhcp_address_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        struct in_addr address;
        Link *link;
        int r;

        assert(acd);
        assert(userdata);

        link = userdata;

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                log_link_debug(link, "Stopping ACD client for DHCPv4 address.");
                return;

        case SD_IPV4ACD_EVENT_BIND:
                if (DEBUG_LOGGING) {
                        (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address);
                        log_link_debug(link, "Successfully claimed DHCPv4 address "IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address));
                }
                link->dhcp4_address_bind = true;
                dhcp4_check_ready(link);
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address);
                log_link_warning(link, "DAD conflict. Dropping DHCPv4 address "IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address));

                r = sd_dhcp_client_send_decline(link->dhcp_client);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to send DHCP DECLINE, ignoring: %m");

                if (link->dhcp_lease) {
                        r = dhcp_lease_lost(link);
                        if (r < 0)
                                link_enter_failed(link);
                }
                break;

        default:
                assert_not_reached("Invalid IPv4ACD event.");
        }

        (void) sd_ipv4acd_stop(acd);

        return;
}

static int dhcp4_configure_dad(Link *link) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);

        if (!link->network->dhcp_send_decline)
                return 0;

        if (!link->dhcp_acd) {
                r = sd_ipv4acd_new(&link->dhcp_acd);
                if (r < 0)
                        return r;

                r = sd_ipv4acd_attach_event(link->dhcp_acd, link->manager->event, 0);
                if (r < 0)
                        return r;
        }

        r = sd_ipv4acd_set_ifindex(link->dhcp_acd, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(link->dhcp_acd, &link->hw_addr.addr.ether);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp4_dad_update_mac(Link *link) {
        bool running;
        int r;

        assert(link);

        if (!link->dhcp_acd)
                return 0;

        running = sd_ipv4acd_is_running(link->dhcp_acd);

        r = sd_ipv4acd_stop(link->dhcp_acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(link->dhcp_acd, &link->hw_addr.addr.ether);
        if (r < 0)
                return r;

        if (running) {
                r = sd_ipv4acd_start(link->dhcp_acd, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp4_start_acd(Link *link) {
        struct in_addr addr, old;
        int r;

        if (!link->network->dhcp_send_decline)
                return 0;

        if (!link->dhcp_lease)
                return 0;

        (void) sd_ipv4acd_stop(link->dhcp_acd);

        link->dhcp4_address_bind = false;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &addr);
        if (r < 0)
                return r;

        r = sd_ipv4acd_get_address(link->dhcp_acd, &old);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_address(link->dhcp_acd, &addr);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(link->dhcp_acd, dhcp_address_on_acd, link);
        if (r < 0)
                return r;

        log_link_debug(link, "Starting IPv4ACD client. Probing DHCPv4 address "IPV4_ADDRESS_FMT_STR,
                       IPV4_ADDRESS_FMT_VAL(addr));

        return sd_ipv4acd_start(link->dhcp_acd, !in4_addr_equal(&addr, &old));
}

static int dhcp4_address_ready_callback(Address *address) {
        Link *link;
        int r;

        assert(address);

        link = address->link;

        /* Do not call this again. */
        address->callback = NULL;

        r = link_set_dhcp_routes(link);
        if (r < 0)
                return r;

        /* Reconfigure static routes as kernel may remove some routes when lease expires. */
        r = link_set_routes(link);
        if (r < 0)
                return r;

        r = dhcp4_start_acd(link);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to start IPv4ACD for DHCP4 address: %m");

        dhcp4_check_ready(link);
        return 0;
}

static int dhcp4_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set DHCPv4 address");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (address_is_ready(link->dhcp_address)) {
                r = dhcp4_address_ready_callback(link->dhcp_address);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        } else
                link->dhcp_address->callback = dhcp4_address_ready_callback;

        return 1;
}

static int dhcp4_update_address(Link *link, bool announce) {
        _cleanup_(address_freep) Address *addr = NULL;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;
        struct in_addr address, netmask;
        unsigned prefixlen;
        Address *ret;
        int r;

        assert(link);
        assert(link->network);

        if (!link->dhcp_lease)
                return 0;

        link_set_state(link, LINK_STATE_CONFIGURING);
        link->dhcp4_configured = false;

        /* address_handler calls link_set_routes() and link_set_nexthop(). Before they are called, the
         * related flags must be cleared. Otherwise, the link becomes configured state before routes
         * are configured. */
        link->static_routes_configured = false;
        link->static_nexthops_configured = false;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no address: %m");

        r = sd_dhcp_lease_get_netmask(link->dhcp_lease, &netmask);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no netmask: %m");

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                r = sd_dhcp_lease_get_lifetime(link->dhcp_lease, &lifetime);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP error: no lifetime: %m");
        }

        prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

        if (announce) {
                const struct in_addr *router;

                r = sd_dhcp_lease_get_router(link->dhcp_lease, &router);
                if (r < 0 && r != -ENODATA)
                        return log_link_error_errno(link, r, "DHCP error: Could not get gateway: %m");

                if (r > 0 && in4_addr_is_set(&router[0]))
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address "IPV4_ADDRESS_FMT_STR"/%u via "IPV4_ADDRESS_FMT_STR,
                                                    IPV4_ADDRESS_FMT_VAL(address),
                                                    prefixlen,
                                                    IPV4_ADDRESS_FMT_VAL(router[0])),
                                   "ADDRESS="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address),
                                   "PREFIXLEN=%u", prefixlen,
                                   "GATEWAY="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(router[0]));
                else
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address "IPV4_ADDRESS_FMT_STR"/%u",
                                                    IPV4_ADDRESS_FMT_VAL(address),
                                                    prefixlen),
                                   "ADDRESS="IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(address),
                                   "PREFIXLEN=%u", prefixlen);
        }

        r = address_new(&addr);
        if (r < 0)
                return log_oom();

        addr->family = AF_INET;
        addr->in_addr.in.s_addr = address.s_addr;
        addr->cinfo.ifa_prefered = lifetime;
        addr->cinfo.ifa_valid = lifetime;
        addr->prefixlen = prefixlen;
        if (prefixlen <= 30)
                addr->broadcast.s_addr = address.s_addr | ~netmask.s_addr;
        SET_FLAG(addr->flags, IFA_F_NOPREFIXROUTE, !link_prefixroute(link));
        addr->route_metric = link->network->dhcp_route_metric;

        /* allow reusing an existing address and simply update its lifetime
         * in case it already exists */
        r = address_configure(addr, link, dhcp4_address_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set DHCPv4 address: %m");

        if (!address_equal(link->dhcp_address, ret))
                link->dhcp_address_old = link->dhcp_address;
        link->dhcp_address = ret;

        return 0;
}

static int dhcp_lease_renew(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        int r;

        assert(link);
        assert(client);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no lease: %m");

        sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp_lease = sd_dhcp_lease_ref(lease);
        link_dirty(link);

        return dhcp4_update_address(link, false);
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
                        r = link_set_mtu(link, mtu);
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

        if (link->dhcp4_remove_messages == 0) {
                r = dhcp4_update_address(link, true);
                if (r < 0)
                        return r;
        } else
                log_link_debug(link,
                               "The link has previously assigned DHCPv4 address or routes. "
                               "The newly assigned address and routes will set up after old ones are removed.");

        return 0;
}

static int dhcp_lease_ip_change(sd_dhcp_client *client, Link *link) {
        int r;

        r = dhcp_lease_acquired(client, link);
        if (r < 0)
                (void) dhcp_lease_lost(link);

        return r;
}

static int dhcp_server_is_deny_listed(Link *link, sd_dhcp_client *client) {
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

        if (set_contains(link->network->dhcp_deny_listed_ip, UINT32_TO_PTR(addr.s_addr))) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_LINK_MESSAGE(link, "DHCPv4 server IP address "IPV4_ADDRESS_FMT_STR" found in deny-list, ignoring offer",
                                            IPV4_ADDRESS_FMT_VAL(addr)));
                return true;
        }

        return false;
}

static int dhcp_server_is_allow_listed(Link *link, sd_dhcp_client *client) {
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

        if (set_contains(link->network->dhcp_allow_listed_ip, UINT32_TO_PTR(addr.s_addr))) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_LINK_MESSAGE(link, "DHCPv4 server IP address "IPV4_ADDRESS_FMT_STR" found in allow-list, accepting offer",
                                            IPV4_ADDRESS_FMT_VAL(addr)));
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

                                r = dhcp_lease_lost(link);
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
                                r = dhcp_lease_lost(link);
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
                        if (!set_isempty(link->network->dhcp_allow_listed_ip)) {
                                r = dhcp_server_is_allow_listed(link, client);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -ENOMSG;
                        } else {
                                r = dhcp_server_is_deny_listed(link, client);
                                if (r < 0)
                                        return r;
                                if (r != 0)
                                        return -ENOMSG;
                        }
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
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to get hostname: %m");

                hn = hostname;
        }

        r = sd_dhcp_client_set_hostname(link->dhcp_client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_debug_errno(link, r, "DHCP4 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set hostname: %m");

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
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set IAID+DUID: %m");
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
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set DUID: %m");
                break;
        }
        case DHCP_CLIENT_ID_MAC: {
                const uint8_t *hw_addr = link->hw_addr.addr.bytes;
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
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set client ID: %m");
                break;
        }
        default:
                assert_not_reached("Unknown client identifier type.");
        }

        return 0;
}

static int dhcp4_configure_duid(Link *link) {
        assert(link);

        if (!IN_SET(link->network->dhcp_client_identifier, DHCP_CLIENT_ID_DUID, DHCP_CLIENT_ID_DUID_ONLY))
                return 1;

        return dhcp_configure_duid(link, link_get_dhcp4_duid(link));
}

static int dhcp4_set_request_address(Link *link) {
        Address *a;

        assert(link);
        assert(link->network);
        assert(link->dhcp_client);

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                return 0;

        SET_FOREACH(a, link->addresses_foreign) {
                if (a->family != AF_INET)
                        continue;
                if (link_address_is_dynamic(link, a))
                        break;
        }

        if (!a)
                return 0;

        log_link_debug(link, "DHCP4 CLIENT: requesting " IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(a->in_addr.in));

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
                        log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to parse ID_NET_DHCP_BROADCAST, ignoring: %m");
                else
                        log_link_debug(link, "DHCP4 CLIENT: Detected ID_NET_DHCP_BROADCAST='%d'.", r);

        }
        return r == true;
}

int dhcp4_configure(Link *link) {
        sd_dhcp_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);

        if (!link_dhcp4_enabled(link))
                return 0;

        if (link->dhcp_client)
                return -EBUSY; /* Already configured. */

        r = dhcp4_configure_duid(link);
        if (r <= 0)
                return r;

        r = sd_dhcp_client_new(&link->dhcp_client, link->network->dhcp_anonymize);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to allocate DHCP4 client: %m");

        r = sd_dhcp_client_attach_event(link->dhcp_client, link->manager->event, 0);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to attach event to DHCP4 client: %m");

        r = sd_dhcp_client_set_mac(link->dhcp_client,
                                   link->hw_addr.addr.bytes,
                                   link->bcast_addr.length > 0 ? link->bcast_addr.addr.bytes : NULL,
                                   link->hw_addr.length, link->iftype);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set MAC address: %m");

        r = sd_dhcp_client_set_ifindex(link->dhcp_client, link->ifindex);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set ifindex: %m");

        r = sd_dhcp_client_set_callback(link->dhcp_client, dhcp4_handler, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set callback: %m");

        r = sd_dhcp_client_set_request_broadcast(link->dhcp_client, link_needs_dhcp_broadcast(link));
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for broadcast: %m");

        if (link->mtu > 0) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set MTU: %m");
        }

        if (!link->network->dhcp_anonymize) {
                if (link->network->dhcp_use_mtu) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_INTERFACE_MTU);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for MTU: %m");
                }

                if (link->network->dhcp_use_routes) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_STATIC_ROUTE);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for static route: %m");

                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for classless static route: %m");
                }

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_DOMAIN_SEARCH_LIST);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for domain search list: %m");
                }

                if (link->network->dhcp_use_ntp) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NTP_SERVER);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for NTP server: %m");
                }

                if (link->network->dhcp_use_sip) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_SIP_SERVER);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for SIP server: %m");
                }

                if (link->network->dhcp_use_timezone) {
                        r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NEW_TZDB_TIMEZONE);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for timezone: %m");
                }

                SET_FOREACH(request_options, link->network->dhcp_request_options) {
                        uint32_t option = PTR_TO_UINT32(request_options);

                        r = sd_dhcp_client_set_request_option(link->dhcp_client, option);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for '%u': %m", option);
                }

                ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_options) {
                        r = sd_dhcp_client_add_option(link->dhcp_client, send_option);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set send option: %m");
                }

                ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_vendor_options) {
                        r = sd_dhcp_client_add_vendor_option(link->dhcp_client, send_option);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set send option: %m");
                }

                r = dhcp4_set_hostname(link);
                if (r < 0)
                        return r;

                if (link->network->dhcp_vendor_class_identifier) {
                        r = sd_dhcp_client_set_vendor_class_identifier(link->dhcp_client,
                                                                       link->network->dhcp_vendor_class_identifier);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set vendor class identifier: %m");
                }

                if (link->network->dhcp_mudurl) {
                        r = sd_dhcp_client_set_mud_url(link->dhcp_client, link->network->dhcp_mudurl);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set MUD URL: %m");
                }

                if (link->network->dhcp_user_class) {
                        r = sd_dhcp_client_set_user_class(link->dhcp_client, link->network->dhcp_user_class);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set user class: %m");
                }
        }

        if (link->network->dhcp_client_port > 0) {
                r = sd_dhcp_client_set_client_port(link->dhcp_client, link->network->dhcp_client_port);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set listen port: %m");
        }

        if (link->network->dhcp_max_attempts > 0) {
                r = sd_dhcp_client_set_max_attempts(link->dhcp_client, link->network->dhcp_max_attempts);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set max attempts: %m");
        }

        if (link->network->dhcp_ip_service_type > 0) {
                r = sd_dhcp_client_set_service_type(link->dhcp_client, link->network->dhcp_ip_service_type);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set IP service type: %m");
        }

        if (link->network->dhcp_fallback_lease_lifetime > 0) {
                r = sd_dhcp_client_set_fallback_lease_lifetime(link->dhcp_client, link->network->dhcp_fallback_lease_lifetime);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed set to lease lifetime: %m");
        }

        r = dhcp4_set_request_address(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set initial DHCPv4 address: %m");

        r = dhcp4_configure_dad(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to configure service type: %m");

        return dhcp4_set_client_identifier(link);
}

int dhcp4_update_mac(Link *link) {
        int r;

        assert(link);

        if (!link->dhcp_client)
                return 0;

        r = sd_dhcp_client_set_mac(link->dhcp_client, link->hw_addr.addr.bytes,
                                   link->bcast_addr.length > 0 ? link->bcast_addr.addr.bytes : NULL,
                                   link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        r = dhcp4_set_client_identifier(link);
        if (r < 0)
                return r;

        r = dhcp4_dad_update_mac(link);
        if (r < 0)
                return r;

        return 0;
}

int dhcp4_start(Link *link) {
        assert(link);

        if (!link->dhcp_client)
                return 0;

        if (sd_dhcp_client_is_running(link->dhcp_client) > 0)
                return 0;

        log_link_debug(link, "Acquiring DHCPv4 lease");

        return sd_dhcp_client_start(link->dhcp_client);
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

int config_parse_dhcp_acl_ip_address(
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
        Set **acl;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        acl = STR_IN_SET(lvalue, "DenyList", "BlackList") ? &network->dhcp_deny_listed_ip : &network->dhcp_allow_listed_ip;

        if (isempty(rvalue)) {
                *acl = set_free(*acl);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *n = NULL;
                union in_addr_union ip;

                r = extract_first_word(&p, &n, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DHCP '%s=' IP address, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, n, &ip);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "DHCP '%s=' IP address is invalid, ignoring assignment: %s", lvalue, n);
                        continue;
                }

                r = set_ensure_put(acl, NULL, UINT32_TO_PTR(ip.in.s_addr));
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store DHCP '%s=' IP address '%s', ignoring assignment: %m", lvalue, n);
        }
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "CS4"))
                *((int *)data) = IPTOS_CLASS_CS4;
        else if (streq(rvalue, "CS6"))
                *((int *)data) = IPTOS_CLASS_CS6;
        else
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse IPServiceType type '%s', ignoring.", rvalue);

        return 0;
}

int config_parse_dhcp_mud_url(
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

        _cleanup_free_ char *unescaped = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp_mudurl = mfree(network->dhcp_mudurl);
                return 0;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to Failed to unescape MUD URL, ignoring: %s", rvalue);
                return 0;
        }

        if (!http_url_is_valid(unescaped) || strlen(unescaped) > 255) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse MUD URL '%s', ignoring: %m", rvalue);

                return 0;
        }

        return free_and_strdup_warn(&network->dhcp_mudurl, unescaped);
}

int config_parse_dhcp_fallback_lease_lifetime(const char *unit,
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
        uint32_t k;

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
        if (STR_IN_SET(rvalue, "forever", "infinity"))
                k = CACHE_INFO_INFINITY_LIFE_TIME;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid LeaseLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        network->dhcp_fallback_lease_lifetime = k;

        return 0;
}

static const char* const dhcp_client_identifier_table[_DHCP_CLIENT_ID_MAX] = {
        [DHCP_CLIENT_ID_MAC] = "mac",
        [DHCP_CLIENT_ID_DUID] = "duid",
        [DHCP_CLIENT_ID_DUID_ONLY] = "duid-only",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_client_identifier, DHCPClientIdentifier);
DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp_client_identifier, dhcp_client_identifier, DHCPClientIdentifier,
                         "Failed to parse client identifier type");
