/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "escape.h"
#include "alloc-util.h"
#include "dhcp-client-internal.h"
#include "hostname-util.h"
#include "parse-util.h"
#include "network-internal.h"
#include "networkd-dhcp4.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "web-util.h"

static int dhcp4_update_address(Link *link, bool announce);
static int dhcp4_remove_all(Link *link);

static int dhcp4_release_old_lease(Link *link) {
        Route *route;
        int k, r = 0;

        assert(link);

        if (!link->dhcp_address_old && set_isempty(link->dhcp_routes_old))
                return 0;

        log_link_debug(link, "Removing old DHCPv4 address and routes.");

        link_dirty(link);

        SET_FOREACH(route, link->dhcp_routes_old) {
                k = route_remove(route, link, NULL);
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

static int route_scope_from_address(const Route *route, const struct in_addr *self_addr) {
        assert(route);
        assert(self_addr);

        if (in4_addr_is_localhost(&route->dst.in) ||
            (!in4_addr_is_null(self_addr) && in4_addr_equal(&route->dst.in, self_addr)))
                return RT_SCOPE_HOST;
        else if (in4_addr_is_null(&route->gw.in))
                return RT_SCOPE_LINK;
        else
                return RT_SCOPE_UNIVERSE;
}

static bool link_prefixroute(Link *link) {
        return !link->network->dhcp_route_table_set ||
                link->network->dhcp_route_table == RT_TABLE_MAIN ||
                link->manager->dhcp4_prefix_root_cannot_set_table;
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

static int link_set_dns_routes(Link *link, const struct in_addr *address) {
        const struct in_addr *dns;
        uint32_t table;
        int i, n, r;

        assert(link);
        assert(link->dhcp_lease);
        assert(link->network);

        if (!link->network->dhcp_use_dns ||
            !link->network->dhcp_routes_to_dns)
                return 0;

        n = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
        if (IN_SET(n, 0, -ENODATA))
                return 0;
        if (n < 0)
                return log_link_warning_errno(link, n, "DHCP error: could not get DNS servers: %m");

        table = link_get_dhcp_route_table(link);

        for (i = 0; i < n; i ++) {
                _cleanup_(route_freep) Route *route = NULL;

                r = route_new(&route);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not allocate route: %m");

                /* Set routes to DNS servers. */

                route->family = AF_INET;
                route->dst.in = dns[i];
                route->dst_prefixlen = 32;
                route->prefsrc.in = *address;
                route->scope = RT_SCOPE_LINK;
                route->protocol = RTPROT_DHCP;
                route->priority = link->network->dhcp_route_metric;
                route->table = table;

                r = dhcp_route_configure(route, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set route to DNS server: %m");
        }

        return 0;
}

static int dhcp_prefix_route_from_lease(
                const sd_dhcp_lease *lease,
                uint32_t table,
                const struct in_addr *address,
                Route **ret_route) {

        Route *route;
        struct in_addr netmask;
        int r;

        r = sd_dhcp_lease_get_netmask((sd_dhcp_lease*) lease, &netmask);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->dst.in.s_addr = address->s_addr & netmask.s_addr;
        route->dst_prefixlen = in4_addr_netmask_to_prefixlen(&netmask);
        route->prefsrc.in = *address;
        route->scope = RT_SCOPE_LINK;
        route->protocol = RTPROT_DHCP;
        route->table = table;
        *ret_route = route;
        return 0;
}

static int link_set_dhcp_routes(Link *link) {
        _cleanup_free_ sd_dhcp_route **static_routes = NULL;
        bool classless_route = false, static_route = false;
        struct in_addr address;
        uint32_t table;
        Route *rt;
        int r, n;

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

        table = link_get_dhcp_route_table(link);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: could not get address: %m");

        if (!link_prefixroute(link)) {
                _cleanup_(route_freep) Route *prefix_route = NULL;

                r = dhcp_prefix_route_from_lease(link->dhcp_lease, table, &address, &prefix_route);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not create prefix route: %m");

                r = dhcp_route_configure(prefix_route, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set prefix route: %m");
        }

        n = sd_dhcp_lease_get_routes(link->dhcp_lease, &static_routes);
        if (n == -ENODATA)
                log_link_debug_errno(link, n, "DHCP: No routes received from DHCP server: %m");
        else if (n < 0)
                return log_link_error_errno(link, n, "DHCP: could not get routes: %m");

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

        if (link->network->dhcp_use_routes) {
                /* if the DHCP server returns both a Classless Static Routes option and a Static Routes option,
                 * the DHCP client MUST ignore the Static Routes option. */
                if (classless_route && static_route)
                        log_link_warning(link, "Classless static routes received from DHCP server: ignoring static-route option");

                for (int i = 0; i < n; i++) {
                        _cleanup_(route_freep) Route *route = NULL;

                        if (classless_route &&
                            sd_dhcp_route_get_option(static_routes[i]) != SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE)
                                continue;

                        r = route_new(&route);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not allocate route: %m");

                        route->family = AF_INET;
                        route->protocol = RTPROT_DHCP;
                        assert_se(sd_dhcp_route_get_gateway(static_routes[i], &route->gw.in) >= 0);
                        assert_se(sd_dhcp_route_get_destination(static_routes[i], &route->dst.in) >= 0);
                        assert_se(sd_dhcp_route_get_destination_prefix_length(static_routes[i], &route->dst_prefixlen) >= 0);
                        route->priority = link->network->dhcp_route_metric;
                        route->table = table;
                        route->mtu = link->network->dhcp_route_mtu;
                        route->scope = route_scope_from_address(route, &address);
                        if (IN_SET(route->scope, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE))
                                route->prefsrc.in = address;

                        if (set_contains(link->dhcp_routes, route))
                                continue;

                        r = dhcp_route_configure(route, link);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set route: %m");
                }
        }

        if (link->network->dhcp_use_gateway) {
                const struct in_addr *router;

                r = sd_dhcp_lease_get_router(link->dhcp_lease, &router);
                if (IN_SET(r, 0, -ENODATA))
                        log_link_info(link, "DHCP: No gateway received from DHCP server.");
                else if (r < 0)
                        return log_link_error_errno(link, r, "DHCP error: could not get gateway: %m");
                else if (in4_addr_is_null(&router[0]))
                        log_link_info(link, "DHCP: Received gateway is null.");
                else if (classless_route)
                        /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
                         * a Router option, the DHCP client MUST ignore the Router option. */
                        log_link_warning(link, "Classless static routes received from DHCP server: ignoring router option");
                else {
                        _cleanup_(route_freep) Route *route = NULL, *route_gw = NULL;

                        r = route_new(&route_gw);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not allocate route: %m");

                        /* The dhcp netmask may mask out the gateway. Add an explicit
                         * route for the gw host so that we can route no matter the
                         * netmask or existing kernel route tables. */
                        route_gw->family = AF_INET;
                        route_gw->dst.in = router[0];
                        route_gw->dst_prefixlen = 32;
                        route_gw->prefsrc.in = address;
                        route_gw->scope = RT_SCOPE_LINK;
                        route_gw->protocol = RTPROT_DHCP;
                        route_gw->priority = link->network->dhcp_route_metric;
                        route_gw->table = table;
                        route_gw->mtu = link->network->dhcp_route_mtu;

                        r = dhcp_route_configure(route_gw, link);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set host route: %m");

                        r = route_new(&route);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not allocate route: %m");

                        route->family = AF_INET;
                        route->gw.in = router[0];
                        route->prefsrc.in = address;
                        route->protocol = RTPROT_DHCP;
                        route->priority = link->network->dhcp_route_metric;
                        route->table = table;
                        route->mtu = link->network->dhcp_route_mtu;

                        r = dhcp_route_configure(route, link);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Could not set router: %m");

                        LIST_FOREACH(routes, rt, link->network->static_routes) {
                                if (!rt->gateway_from_dhcp)
                                        continue;

                                if (rt->family != AF_INET)
                                        continue;

                                rt->gw.in = router[0];

                                r = dhcp_route_configure(rt, link);
                                if (r < 0)
                                        return log_link_error_errno(link, r, "Could not set gateway: %m");
                        }
                }
        }

        return link_set_dns_routes(link, &address);
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
                k = route_remove(route, link, dhcp4_remove_route_handler);
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

        return r;
}

static void dhcp_address_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        _cleanup_free_ char *pretty = NULL;
        union in_addr_union address = {};
        Link *link;
        int r;

        assert(acd);
        assert(userdata);

        link = userdata;

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                log_link_debug(link, "Stopping ACD client for DHCP4...");
                return;

        case SD_IPV4ACD_EVENT_BIND:
                if (DEBUG_LOGGING) {
                        (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address.in);
                        (void) in_addr_to_string(AF_INET, &address, &pretty);
                        log_link_debug(link, "Successfully claimed DHCP4 address %s", strna(pretty));
                }
                link->dhcp4_address_bind = true;
                dhcp4_check_ready(link);
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address.in);
                (void) in_addr_to_string(AF_INET, &address, &pretty);
                log_link_warning(link, "DAD conflict. Dropping DHCP4 address %s", strna(pretty));

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

static int configure_dhcpv4_duplicate_address_detection(Link *link) {
        int r;

        assert(link);

        r = sd_ipv4acd_new(&link->network->dhcp_acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_attach_event(link->network->dhcp_acd, NULL, 0);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_ifindex(link->network->dhcp_acd, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(link->network->dhcp_acd, &link->mac);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp4_start_acd(Link *link) {
        union in_addr_union addr;
        struct in_addr old;
        int r;

        if (!link->network->dhcp_send_decline)
                return 0;

        if (!link->dhcp_lease)
                return 0;

        (void) sd_ipv4acd_stop(link->network->dhcp_acd);

        link->dhcp4_address_bind = false;

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_get_address(link->network->dhcp_acd, &old);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_address(link->network->dhcp_acd, &addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(link->network->dhcp_acd, dhcp_address_on_acd, link);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *pretty = NULL;

                (void) in_addr_to_string(AF_INET, &addr, &pretty);
                log_link_debug(link, "Starting IPv4ACD client. Probing DHCPv4 address %s", strna(pretty));
        }

        r = sd_ipv4acd_start(link->network->dhcp_acd, !in4_addr_equal(&addr.in, &old));
        if (r < 0)
                return r;

        return 1;
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
        r = link_request_set_routes(link);
        if (r < 0)
                return r;

        r = dhcp4_start_acd(link);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to start IPv4ACD for DHCP4 adddress: %m");

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

        /* address_handler calls link_request_set_routes() and link_request_set_nexthop(). Before they
         * are called, the related flags must be cleared. Otherwise, the link becomes configured state
         * before routes are configured. */
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

                if (r > 0 && !in4_addr_is_null(&router[0]))
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address %u.%u.%u.%u/%u via %u.%u.%u.%u",
                                                    ADDRESS_FMT_VAL(address),
                                                    prefixlen,
                                                    ADDRESS_FMT_VAL(router[0])),
                                   "ADDRESS=%u.%u.%u.%u", ADDRESS_FMT_VAL(address),
                                   "PREFIXLEN=%u", prefixlen,
                                   "GATEWAY=%u.%u.%u.%u", ADDRESS_FMT_VAL(router[0]));
                else
                        log_struct(LOG_INFO,
                                   LOG_LINK_INTERFACE(link),
                                   LOG_LINK_MESSAGE(link, "DHCPv4 address %u.%u.%u.%u/%u",
                                                    ADDRESS_FMT_VAL(address),
                                                    prefixlen),
                                   "ADDRESS=%u.%u.%u.%u", ADDRESS_FMT_VAL(address),
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
        addr->broadcast.s_addr = address.s_addr | ~netmask.s_addr;
        addr->prefix_route = link_prefixroute(link);

        /* allow reusing an existing address and simply update its lifetime
         * in case it already exists */
        r = address_configure(addr, link, dhcp4_address_handler, true, &ret);
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
                           LOG_LINK_MESSAGE(link, "DHCPv4 IP '%u.%u.%u.%u' found in deny-listed IP addresses, ignoring offer",
                                            ADDRESS_FMT_VAL(addr)));
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
                           LOG_LINK_MESSAGE(link, "DHCPv4 IP '%u.%u.%u.%u' found in allow-listed IP addresses, accepting offer",
                                            ADDRESS_FMT_VAL(addr)));
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

                        if (link_ipv4ll_enabled(link, ADDRESS_FAMILY_FALLBACK_IPV4)) {
                                assert(link->ipv4ll);

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
                                                log_link_warning_errno(link, r, "Failed to send DHCP RELEASE, ignoring: %m");
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
                        return r;

                hn = hostname;
        }

        r = sd_dhcp_client_set_hostname(link->dhcp_client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_warning_errno(link, r, "DHCP4 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set hostname: %m");

        return 0;
}

static bool promote_secondaries_enabled(const char *ifname) {
        _cleanup_free_ char *promote_secondaries_sysctl = NULL;
        char *promote_secondaries_path;
        int r;

        promote_secondaries_path = strjoina("net/ipv4/conf/", ifname, "/promote_secondaries");
        r = sysctl_read(promote_secondaries_path, &promote_secondaries_sysctl);
        if (r < 0) {
                log_debug_errno(r, "Cannot read sysctl %s", promote_secondaries_path);
                return false;
        }

        truncate_nl(promote_secondaries_sysctl);
        r = parse_boolean(promote_secondaries_sysctl);
        if (r < 0)
                log_warning_errno(r, "Cannot parse sysctl %s with content %s as boolean", promote_secondaries_path, promote_secondaries_sysctl);
        return r > 0;
}

/* dhcp4_set_promote_secondaries will ensure this interface has
 * the "promote_secondaries" option in the kernel set. If this sysctl
 * is not set DHCP will work only as long as the IP address does not
 * changes between leases. The kernel will remove all secondary IP
 * addresses of an interface otherwise. The way systemd-network works
 * is that the new IP of a lease is added as a secondary IP and when
 * the primary one expires it relies on the kernel to promote the
 * secondary IP. See also https://github.com/systemd/systemd/issues/7163
 */
int dhcp4_set_promote_secondaries(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->dhcp & ADDRESS_FAMILY_IPV4);

        /* check if the kernel has promote_secondaries enabled for our
         * interface. If it is not globally enabled or enabled for the
         * specific interface we must either enable it.
         */
        if (!(promote_secondaries_enabled("all") || promote_secondaries_enabled(link->ifname))) {
                char *promote_secondaries_path = NULL;

                log_link_debug(link, "promote_secondaries is unset, setting it");
                promote_secondaries_path = strjoina("net/ipv4/conf/", link->ifname, "/promote_secondaries");
                r = sysctl_write(promote_secondaries_path, "1");
                if (r < 0)
                        log_link_warning_errno(link, r, "cannot set sysctl %s to 1", promote_secondaries_path);
                return r > 0;
        }

        return 0;
}

int dhcp4_set_client_identifier(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp_client);

        switch (link->network->dhcp_client_identifier) {
        case DHCP_CLIENT_ID_DUID: {
                /* If configured, apply user specified DUID and IAID */
                const DUID *duid = link_get_duid(link);

                if (duid->type == DUID_TYPE_LLT && duid->raw_data_len == 0)
                        r = sd_dhcp_client_set_iaid_duid_llt(link->dhcp_client,
                                                             link->network->iaid_set,
                                                             link->network->iaid,
                                                             duid->llt_time);
                else
                        r = sd_dhcp_client_set_iaid_duid(link->dhcp_client,
                                                         link->network->iaid_set,
                                                         link->network->iaid,
                                                         duid->type,
                                                         duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                         duid->raw_data_len);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set IAID+DUID: %m");
                break;
        }
        case DHCP_CLIENT_ID_DUID_ONLY: {
                /* If configured, apply user specified DUID */
                const DUID *duid = link_get_duid(link);

                if (duid->type == DUID_TYPE_LLT && duid->raw_data_len == 0)
                        r = sd_dhcp_client_set_duid_llt(link->dhcp_client,
                                                        duid->llt_time);
                else
                        r = sd_dhcp_client_set_duid(link->dhcp_client,
                                                    duid->type,
                                                    duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                                    duid->raw_data_len);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set DUID: %m");
                break;
        }
        case DHCP_CLIENT_ID_MAC:
                r = sd_dhcp_client_set_client_id(link->dhcp_client,
                                                 ARPHRD_ETHER,
                                                 (const uint8_t *) &link->mac,
                                                 sizeof(link->mac));
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set client ID: %m");
                break;
        default:
                assert_not_reached("Unknown client identifier type.");
        }

        return 0;
}

int dhcp4_configure(Link *link) {
        sd_dhcp_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->dhcp & ADDRESS_FAMILY_IPV4);

        if (!link->dhcp_client) {
                r = sd_dhcp_client_new(&link->dhcp_client, link->network->dhcp_anonymize);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to create DHCP4 client: %m");

                r = sd_dhcp_client_attach_event(link->dhcp_client, NULL, 0);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to attach event: %m");
        }

        r = sd_dhcp_client_set_mac(link->dhcp_client,
                                   (const uint8_t *) &link->mac,
                                   sizeof (link->mac), ARPHRD_ETHER);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set MAC address: %m");

        r = sd_dhcp_client_set_ifindex(link->dhcp_client, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set ifindex: %m");

        r = sd_dhcp_client_set_callback(link->dhcp_client, dhcp4_handler, link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set callback: %m");

        r = sd_dhcp_client_set_request_broadcast(link->dhcp_client,
                                                 link->network->dhcp_broadcast);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for broadcast: %m");

        if (link->mtu) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set MTU: %m");
        }

        if (link->network->dhcp_use_mtu) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                      SD_DHCP_OPTION_INTERFACE_MTU);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for MTU: %m");
        }

        /* NOTE: even if this variable is called "use", it also "sends" PRL
         * options, maybe there should be a different configuration variable
         * to send or not route options?. */
        /* NOTE: when using Anonymize=yes, routes PRL options are sent
         * by default, so they don't need to be added here. */
        if (link->network->dhcp_use_routes && !link->network->dhcp_anonymize) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                      SD_DHCP_OPTION_STATIC_ROUTE);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for static route: %m");

                r = sd_dhcp_client_set_request_option(link->dhcp_client,
                                                      SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for classless static route: %m");
        }

        if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO && !link->network->dhcp_anonymize) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_DOMAIN_SEARCH_LIST);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for domain search list: %m");
        }

        if (link->network->dhcp_use_ntp) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NTP_SERVER);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for NTP server: %m");
        }

        if (link->network->dhcp_use_sip) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_SIP_SERVER);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for SIP server: %m");
        }

        if (link->network->dhcp_use_timezone) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NEW_TZDB_TIMEZONE);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for timezone: %m");
        }

        SET_FOREACH(request_options, link->network->dhcp_request_options) {
                uint32_t option = PTR_TO_UINT32(request_options);

                r = sd_dhcp_client_set_request_option(link->dhcp_client, option);
                if (r == -EEXIST) {
                        log_link_debug(link, "DHCP4 CLIENT: Failed to set request flag for '%u' already exists, ignoring.", option);
                        continue;
                }
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for '%u': %m", option);
        }

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_options) {
                r = sd_dhcp_client_add_option(link->dhcp_client, send_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set send option: %m");
        }

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp_client_send_vendor_options) {
                r = sd_dhcp_client_add_vendor_option(link->dhcp_client, send_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set send option: %m");
        }

        r = dhcp4_set_hostname(link);
        if (r < 0)
                return r;

        if (link->network->dhcp_vendor_class_identifier) {
                r = sd_dhcp_client_set_vendor_class_identifier(link->dhcp_client,
                                                               link->network->dhcp_vendor_class_identifier);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set vendor class identifier: %m");
        }

       if (link->network->dhcp_mudurl) {
                r = sd_dhcp_client_set_mud_url(link->dhcp_client,
                                               link->network->dhcp_mudurl);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set MUD URL: %m");
        }

        if (link->network->dhcp_user_class) {
                r = sd_dhcp_client_set_user_class(link->dhcp_client, (const char **) link->network->dhcp_user_class);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set user class: %m");
        }

        if (link->network->dhcp_client_port) {
                r = sd_dhcp_client_set_client_port(link->dhcp_client, link->network->dhcp_client_port);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set listen port: %m");
        }

        if (link->network->dhcp_max_attempts > 0) {
                r = sd_dhcp_client_set_max_attempts(link->dhcp_client, link->network->dhcp_max_attempts);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set max attempts: %m");
        }

        if (link->network->ip_service_type > 0) {
                r = sd_dhcp_client_set_service_type(link->dhcp_client, link->network->ip_service_type);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set IP service type: %m");
        }

        if (link->network->dhcp_fallback_lease_lifetime > 0) {
                r = sd_dhcp_client_set_fallback_lease_lifetime(link->dhcp_client, link->network->dhcp_fallback_lease_lifetime);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed set to lease lifetime: %m");
        }

        if (link->network->dhcp_send_decline) {
                r = configure_dhcpv4_duplicate_address_detection(link);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to configure service type: %m");
        }

        return dhcp4_set_client_identifier(link);
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
                network->dhcp_max_attempts = (uint64_t) -1;
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
