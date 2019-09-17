/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "alloc-util.h"
#include "hostname-util.h"
#include "parse-util.h"
#include "network-internal.h"
#include "networkd-dhcp4.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "string-table.h"
#include "string-util.h"
#include "sysctl-util.h"

static int dhcp_remove_routes(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all);
static int dhcp_remove_router(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all);
static int dhcp_remove_dns_routes(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all);
static int dhcp_remove_address(Link *link, sd_dhcp_lease *lease, const struct in_addr *address);

void dhcp4_release_old_lease(Link *link) {
        struct in_addr address = {}, address_old = {};

        assert(link);

        if (!link->dhcp_lease_old)
                return;

        assert(link->dhcp_lease);

        (void) sd_dhcp_lease_get_address(link->dhcp_lease_old, &address_old);
        (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address);

        (void) dhcp_remove_routes(link, link->dhcp_lease_old, &address_old, false);
        (void) dhcp_remove_router(link, link->dhcp_lease_old, &address_old, false);
        (void) dhcp_remove_dns_routes(link, link->dhcp_lease_old, &address_old, false);

        if (!in4_addr_equal(&address_old, &address))
                (void) dhcp_remove_address(link, link->dhcp_lease_old, &address_old);

        link->dhcp_lease_old = sd_dhcp_lease_unref(link->dhcp_lease_old);
        link_dirty(link);
}

static int dhcp4_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp4_messages > 0);

        link->dhcp4_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not set DHCPv4 route: %m");
                link_enter_failed(link);
                return 1;
        }

        if (link->dhcp4_messages == 0) {
                link->dhcp4_configured = true;
                /* New address and routes are configured now. Let's release old lease. */
                dhcp4_release_old_lease(link);
                link_check_ready(link);
        }

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

static int dhcp_route_configure(Route **route, Link *link) {
        int r;

        assert(route);
        assert(*route);
        assert(link);

        if (set_contains(link->dhcp_routes, *route))
                return 0;

        r = route_configure(*route, link, dhcp4_route_handler);
        if (r <= 0)
                return r;

        link->dhcp4_messages++;

        r = set_put(link->dhcp_routes, *route);
        if (r < 0)
                return r;

        TAKE_PTR(*route);
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
                        return log_link_error_errno(link, r,  "Could not allocate route: %m");

                /* Set routes to DNS servers. */

                route->family = AF_INET;
                route->dst.in = dns[i];
                route->dst_prefixlen = 32;
                route->prefsrc.in = *address;
                route->scope = RT_SCOPE_LINK;
                route->protocol = RTPROT_DHCP;
                route->priority = link->network->dhcp_route_metric;
                route->table = table;

                r = dhcp_route_configure(&route, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set route to DNS server: %m");
        }

        return 0;
}

static int link_set_dhcp_routes(Link *link) {
        _cleanup_free_ sd_dhcp_route **static_routes = NULL;
        bool classless_route = false, static_route = false;
        const struct in_addr *router;
        struct in_addr address;
        int r, n, i;
        uint32_t table;

        assert(link);

        if (!link->dhcp_lease) /* link went down while we configured the IP addresses? */
                return 0;

        if (!link->network) /* link went down while we configured the IP addresses? */
                return 0;

        if (!link->network->dhcp_use_routes)
                return 0;

        if (!link_has_carrier(link) && !link->network->configure_without_carrier)
                /* During configuring addresses, the link lost its carrier. As networkd is dropping
                 * the addresses now, let's not configure the routes either. */
                return 0;

        r = set_ensure_allocated(&link->dhcp_routes, &route_hash_ops);
        if (r < 0)
                return log_oom();

        /* Clear old entries in case the set was already allocated */
        set_clear(link->dhcp_routes);

        table = link_get_dhcp_route_table(link);

        r = sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: could not get address: %m");

        n = sd_dhcp_lease_get_routes(link->dhcp_lease, &static_routes);
        if (n == -ENODATA)
                log_link_debug_errno(link, n, "DHCP: No routes received from DHCP server: %m");
        else if (n < 0)
                log_link_debug_errno(link, n, "DHCP: could not get routes: %m");

        for (i = 0; i < n; i++) {
                switch (sd_dhcp_route_get_option(static_routes[i])) {
                case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
                        classless_route = true;
                        break;
                case SD_DHCP_OPTION_STATIC_ROUTE:
                        static_route = true;
                        break;
                }
        }

        for (i = 0; i < n; i++) {
                _cleanup_(route_freep) Route *route = NULL;

                /* if the DHCP server returns both a Classless Static Routes option and a Static Routes option,
                   the DHCP client MUST ignore the Static Routes option. */
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
                route->scope = route_scope_from_address(route, &address);
                if (IN_SET(route->scope, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE))
                        route->prefsrc.in = address;

                if (set_contains(link->dhcp_routes, route))
                        continue;

                r = dhcp_route_configure(&route, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set route: %m");
        }

        r = sd_dhcp_lease_get_router(link->dhcp_lease, &router);
        if (IN_SET(r, 0, -ENODATA))
                log_link_info(link, "DHCP: No gateway received from DHCP server.");
        else if (r < 0)
                log_link_warning_errno(link, r, "DHCP error: could not get gateway: %m");
        else if (in4_addr_is_null(&router[0]))
                log_link_info(link, "DHCP: Received gateway is null.");

        /* According to RFC 3442: If the DHCP server returns both a Classless Static Routes option and
           a Router option, the DHCP client MUST ignore the Router option. */
        if (classless_route && static_route)
                log_link_warning(link, "Classless static routes received from DHCP server: ignoring static-route option and router option");

        if (r > 0 && !classless_route && !in4_addr_is_null(&router[0])) {
                _cleanup_(route_freep) Route *route = NULL, *route_gw = NULL;

                r = route_new(&route_gw);
                if (r < 0)
                        return log_link_error_errno(link, r,  "Could not allocate route: %m");

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

                r = dhcp_route_configure(&route_gw, link);
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

                r = dhcp_route_configure(&route, link);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set router: %m");
        }

        return link_set_dns_routes(link, &address);
}

static int dhcp_remove_routes(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all) {
        _cleanup_free_ sd_dhcp_route **routes = NULL;
        uint32_t table;
        int n, i, r;

        assert(link);
        assert(address);

        if (!link->network->dhcp_use_routes)
                return 0;

        n = sd_dhcp_lease_get_routes(lease, &routes);
        if (IN_SET(n, 0, -ENODATA))
                return 0;
        else if (n < 0)
                return log_link_error_errno(link, n, "DHCP error: Failed to get routes: %m");

        table = link_get_dhcp_route_table(link);

        for (i = 0; i < n; i++) {
                _cleanup_(route_freep) Route *route = NULL;

                r = route_new(&route);
                if (r < 0)
                        return log_oom();

                route->family = AF_INET;
                assert_se(sd_dhcp_route_get_gateway(routes[i], &route->gw.in) >= 0);
                assert_se(sd_dhcp_route_get_destination(routes[i], &route->dst.in) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &route->dst_prefixlen) >= 0);
                route->priority = link->network->dhcp_route_metric;
                route->table = table;
                route->scope = route_scope_from_address(route, address);
                if (IN_SET(route->scope, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE))
                        route->prefsrc.in = *address;

                if (!remove_all && set_contains(link->dhcp_routes, route))
                        continue;

                (void) route_remove(route, link, NULL);
        }

        return n;
}

static int dhcp_remove_router(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all) {
        _cleanup_(route_freep) Route *route_gw = NULL, *route = NULL;
        const struct in_addr *router;
        uint32_t table;
        int r;

        assert(link);
        assert(address);

        if (!link->network->dhcp_use_routes)
                return 0;

        r = sd_dhcp_lease_get_router(lease, &router);
        if (IN_SET(r, 0, -ENODATA)) {
                log_link_debug(link, "DHCP: No gateway received from DHCP server.");
                return 0;
        } else if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: could not get gateway: %m");
        else if (in4_addr_is_null(&router[0])) {
                log_link_info(link, "DHCP: Received gateway is null, ignoring.");
                return 0;
        }

        table = link_get_dhcp_route_table(link);

        r = route_new(&route_gw);
        if (r < 0)
                return log_oom();

        route_gw->family = AF_INET;
        route_gw->dst.in = router[0];
        route_gw->dst_prefixlen = 32;
        route_gw->prefsrc.in = *address;
        route_gw->scope = RT_SCOPE_LINK;
        route_gw->protocol = RTPROT_DHCP;
        route_gw->priority = link->network->dhcp_route_metric;
        route_gw->table = table;

        if (remove_all || !set_contains(link->dhcp_routes, route_gw))
                (void) route_remove(route_gw, link, NULL);

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET;
        route->gw.in = router[0];
        route->prefsrc.in = *address;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_route_metric;
        route->table = table;

        if (remove_all || !set_contains(link->dhcp_routes, route))
                (void) route_remove(route, link, NULL);

        return 0;
}

static int dhcp_remove_dns_routes(Link *link, sd_dhcp_lease *lease, const struct in_addr *address, bool remove_all) {
        const struct in_addr *dns;
        uint32_t table;
        int i, n, r;

        assert(link);
        assert(lease);
        assert(link->network);

        if (!link->network->dhcp_use_dns ||
            !link->network->dhcp_routes_to_dns)
                return 0;

        n = sd_dhcp_lease_get_dns(lease, &dns);
        if (IN_SET(n, 0, -ENODATA))
                return 0;
        if (n < 0)
                return log_link_warning_errno(link, n, "DHCP error: could not get DNS servers: %m");

        table = link_get_dhcp_route_table(link);

        for (i = 0; i < n; i ++) {
                _cleanup_(route_freep) Route *route = NULL;

                r = route_new(&route);
                if (r < 0)
                        return log_link_error_errno(link, r,  "Could not allocate route: %m");

                route->family = AF_INET;
                route->dst.in = dns[i];
                route->dst_prefixlen = 32;
                route->prefsrc.in = *address;
                route->scope = RT_SCOPE_LINK;
                route->protocol = RTPROT_DHCP;
                route->priority = link->network->dhcp_route_metric;
                route->table = table;

                if (!remove_all && set_contains(link->dhcp_routes, route))
                        continue;

                (void) route_remove(route, link, NULL);
        }

        return 0;
}

static int dhcp_remove_address(Link *link, sd_dhcp_lease *lease, const struct in_addr *address) {
        _cleanup_(address_freep) Address *a = NULL;
        struct in_addr netmask;
        int r;

        assert(link);
        assert(address);

        if (in4_addr_is_null(address))
                return 0;

        r = address_new(&a);
        if (r < 0)
                return log_oom();

        a->family = AF_INET;
        a->in_addr.in = *address;

        if (sd_dhcp_lease_get_netmask(lease, &netmask) >= 0)
                a->prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

        (void) address_remove(a, link, NULL);

        return 0;
}

static int dhcp_reset_mtu(Link *link) {
        uint16_t mtu;
        int r;

        assert(link);

        if (!link->network->dhcp_use_mtu)
                return 0;

        r = sd_dhcp_lease_get_mtu(link->dhcp_lease, &mtu);
        if (r < 0)
                return r;

        if (link->original_mtu == mtu)
                return 0;

        r = link_set_mtu(link, link->original_mtu);
        if (r < 0) {
                log_link_error_errno(link, r, "DHCP error: could not reset MTU: %m");
                link_enter_failed(link);
                return r;
        }

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

static int dhcp_lease_lost(Link *link) {
        struct in_addr address = {};

        assert(link);
        assert(link->dhcp_lease);

        log_link_info(link, "DHCP lease lost");

        link->dhcp4_configured = false;

        (void) sd_dhcp_lease_get_address(link->dhcp_lease, &address);
        (void) dhcp_remove_routes(link, link->dhcp_lease, &address, true);
        (void) dhcp_remove_router(link, link->dhcp_lease, &address, true);
        (void) dhcp_remove_dns_routes(link, link->dhcp_lease, &address, true);
        (void) dhcp_remove_address(link, link->dhcp_lease, &address);
        (void) dhcp_reset_mtu(link);
        (void) dhcp_reset_hostname(link);

        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);
        link_dirty(link);

        return 0;
}

static int dhcp4_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not set DHCPv4 address: %m");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        r = link_set_dhcp_routes(link);
        if (r < 0) {
                link_enter_failed(link);
                return 1;
        }

        /* Add back static routes since kernel removes while DHCPv4 address is removed from when lease expires */
        r = link_request_set_routes(link);
        if (r < 0) {
                link_enter_failed(link);
                return 1;
        }

        if (link->dhcp4_messages == 0) {
                link->dhcp4_configured = true;
                /* The new address is configured, and no route is requested.
                 * Let's drop the old lease. */
                dhcp4_release_old_lease(link);
                link_check_ready(link);
        }

        return 1;
}

static int dhcp4_update_address(Link *link,
                                struct in_addr *address,
                                struct in_addr *netmask,
                                uint32_t lifetime) {
        _cleanup_(address_freep) Address *addr = NULL;
        unsigned prefixlen;
        int r;

        assert(address);
        assert(netmask);
        assert(lifetime);

        prefixlen = in4_addr_netmask_to_prefixlen(netmask);

        r = address_new(&addr);
        if (r < 0)
                return r;

        addr->family = AF_INET;
        addr->in_addr.in.s_addr = address->s_addr;
        addr->cinfo.ifa_prefered = lifetime;
        addr->cinfo.ifa_valid = lifetime;
        addr->prefixlen = prefixlen;
        addr->broadcast.s_addr = address->s_addr | ~netmask->s_addr;

        /* allow reusing an existing address and simply update its lifetime
         * in case it already exists */
        r = address_configure(addr, link, dhcp4_address_handler, true);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp_lease_renew(sd_dhcp_client *client, Link *link) {
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;
        int r;

        assert(link);
        assert(client);
        assert(link->network);

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no lease: %m");

        sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp4_configured = false;
        link->dhcp_lease = sd_dhcp_lease_ref(lease);
        link_dirty(link);

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no address: %m");

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0)
                return log_link_warning_errno(link, r, "DHCP error: no netmask: %m");

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                r = sd_dhcp_lease_get_lifetime(link->dhcp_lease, &lifetime);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP error: no lifetime: %m");
        }

        r = dhcp4_update_address(link, &address, &netmask, lifetime);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not update IP address: %m");

        return 0;
}

static int dhcp_lease_acquired(sd_dhcp_client *client, Link *link) {
        const struct in_addr *router;
        sd_dhcp_lease *lease;
        struct in_addr address;
        struct in_addr netmask;
        unsigned prefixlen;
        uint32_t lifetime = CACHE_INFO_INFINITY_LIFE_TIME;
        int r;

        assert(client);
        assert(link);

        link->dhcp4_configured = false;

        r = sd_dhcp_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: No lease: %m");

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: No address: %m");

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP error: No netmask: %m");

        prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

        if (!FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP)) {
                r = sd_dhcp_lease_get_lifetime(lease, &lifetime);
                if (r < 0)
                        return log_link_warning_errno(link, r, "DHCP error: no lifetime: %m");
        }

        r = sd_dhcp_lease_get_router(lease, &router);
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

        r = dhcp4_update_address(link, &address, &netmask, lifetime);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not update IP address: %m");

        return 0;
}

static int dhcp_lease_ip_change(sd_dhcp_client *client, Link *link) {
        int r;

        link->dhcp_lease_old = TAKE_PTR(link->dhcp_lease);

        /* On ip address change, to keep the connectability, we would like to assign new address and
         * routes, and then release old lease. There are two possible success paths:
         *
         * 1. new address and routes are configured.
         *    -> handled by dhcp_release_old_lease() in dhcp4_route_handler().
         * 2. new address is configured and no route is requested.
         *    -> handled by dhcp_release_old_lease() in dhcp4_address_handler().
         *
         * On error in assigning new address and routes, then the link always enters to the failed
         * state. And link_enter_failed() leads to the DHCP client to be stopped. So,
         * dhcp_release_old_lease() will be also called by link_stop_clients().
         */

        r = dhcp_lease_acquired(client, link);
        if (r < 0) {
                /* If it fails, then the new address is not configured yet.
                 * So, let's simply drop the old lease. */
                sd_dhcp_lease_unref(link->dhcp_lease);
                link->dhcp_lease = TAKE_PTR(link->dhcp_lease_old);
                (void) dhcp_lease_lost(link);
                return r;
        }

        return 0;
}

static int dhcp_server_is_black_listed(Link *link, sd_dhcp_client *client) {
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
                return log_link_debug_errno(link, r, "Failed to get DHCP server ip address: %m");

        if (set_contains(link->network->dhcp_black_listed_ip, UINT32_TO_PTR(addr.s_addr))) {
                log_struct(LOG_DEBUG,
                           LOG_LINK_INTERFACE(link),
                           LOG_LINK_MESSAGE(link, "DHCPv4 ip '%u.%u.%u.%u' found in black listed ip addresses, ignoring offer",
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

                        if (link->network->dhcp_send_release)
                                (void) sd_dhcp_client_send_release(client);

                        if (link->dhcp_lease) {
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
                        r = dhcp_server_is_black_listed(link, client);
                        if (r < 0)
                                return r;
                        if (r != 0)
                                return -ENOMSG;
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
        }

        r = sd_dhcp_client_attach_event(link->dhcp_client, NULL, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to attach event: %m");

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

        if (link->network->dhcp_use_timezone) {
                r = sd_dhcp_client_set_request_option(link->dhcp_client, SD_DHCP_OPTION_NEW_TZDB_TIMEZONE);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP4 CLIENT: Failed to set request flag for timezone: %m");
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
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse DHCP maximum attempts, ignoring: %s", rvalue);
                return 0;
        }

        if (a == 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "%s= must be positive integer or 'infinity', ignoring: %s", lvalue, rvalue);
                return 0;
        }

        network->dhcp_max_attempts = a;

        return 0;
}

int config_parse_dhcp_black_listed_ip_address(
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
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->dhcp_black_listed_ip = set_free(network->dhcp_black_listed_ip);
                return 0;
        }

        for (p = rvalue;;) {
                _cleanup_free_ char *n = NULL;
                union in_addr_union ip;

                r = extract_first_word(&p, &n, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DHCP black listed ip address, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, n, &ip);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "DHCP black listed ip address is invalid, ignoring assignment: %s", n);
                        continue;
                }

                r = set_ensure_allocated(&network->dhcp_black_listed_ip, NULL);
                if (r < 0)
                        return log_oom();

                r = set_put(network->dhcp_black_listed_ip, UINT32_TO_PTR(ip.in.s_addr));
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to store DHCP black listed ip address '%s', ignoring assignment: %m", n);
        }

        return 0;
}

int config_parse_dhcp_user_class(
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

        char ***l = data;
        int r;

        assert(l);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *l = strv_free(*l);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&rvalue, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to split user classes option, ignoring: %s", rvalue);
                        break;
                }
                if (r == 0)
                        break;

                if (strlen(w) > 255) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "%s length is not in the range 1-255, ignoring.", w);
                        continue;
                }

                r = strv_push(l, w);
                if (r < 0)
                        return log_oom();

                w = NULL;
        }

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
