/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/ether.h>
#include <linux/if.h>

#include "network-internal.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-link.h"

static int ipv4ll_address_lost(Link *link) {
        _cleanup_(address_freep) Address *address = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr addr;
        int r;

        assert(link);

        link->ipv4ll_route = false;
        link->ipv4ll_address = false;

        r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
        if (r < 0)
                return 0;

        log_link_debug(link, "IPv4 link-local release %u.%u.%u.%u", ADDRESS_FMT_VAL(addr));

        r = address_new(&address);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate address: %m");

        address->family = AF_INET;
        address->in_addr.in = addr;
        address->prefixlen = 16;
        address->scope = RT_SCOPE_LINK;

        address_remove(address, link, NULL);

        r = route_new(&route);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate route: %m");

        route->family = AF_INET;
        route->scope = RT_SCOPE_LINK;
        route->priority = IPV4LL_ROUTE_METRIC;

        route_remove(route, link, NULL);

        link_check_ready(link);

        return 0;
}

static int ipv4ll_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(!link->ipv4ll_route);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "could not set ipv4ll route: %m");
                link_enter_failed(link);
        }

        link->ipv4ll_route = true;

        if (link->ipv4ll_address == true)
                link_check_ready(link);

        return 1;
}

static int ipv4ll_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(!link->ipv4ll_address);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "could not set ipv4ll address: %m");
                link_enter_failed(link);
        } else if (r >= 0)
                manager_rtnl_process_address(rtnl, m, link->manager);

        link->ipv4ll_address = true;

        if (link->ipv4ll_route)
                link_check_ready(link);

        return 1;
}

static int ipv4ll_address_claimed(sd_ipv4ll *ll, Link *link) {
        _cleanup_(address_freep) Address *ll_addr = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        struct in_addr address;
        int r;

        assert(ll);
        assert(link);

        r = sd_ipv4ll_get_address(ll, &address);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                return r;

        log_link_debug(link, "IPv4 link-local claim %u.%u.%u.%u", ADDRESS_FMT_VAL(address));

        r = address_new(&ll_addr);
        if (r < 0)
                return r;

        ll_addr->family = AF_INET;
        ll_addr->in_addr.in = address;
        ll_addr->prefixlen = 16;
        ll_addr->broadcast.s_addr = ll_addr->in_addr.in.s_addr | htobe32(0xfffffffflu >> ll_addr->prefixlen);
        ll_addr->scope = RT_SCOPE_LINK;

        r = address_configure(ll_addr, link, ipv4ll_address_handler, false);
        if (r < 0)
                return r;

        link->ipv4ll_address = false;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->scope = RT_SCOPE_LINK;
        route->protocol = RTPROT_STATIC;
        route->priority = IPV4LL_ROUTE_METRIC;

        r = route_configure(route, link, ipv4ll_route_handler);
        if (r < 0)
                return r;

        link->ipv4ll_route = false;

        return 0;
}

static void ipv4ll_handler(sd_ipv4ll *ll, int event, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
        case SD_IPV4LL_EVENT_STOP:
                r = ipv4ll_address_lost(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }
                break;
        case SD_IPV4LL_EVENT_CONFLICT:
                r = ipv4ll_address_lost(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                r = sd_ipv4ll_restart(ll);
                if (r < 0)
                        log_link_warning(link, "Could not acquire IPv4 link-local address");
                break;
        case SD_IPV4LL_EVENT_BIND:
                r = ipv4ll_address_claimed(ll, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }
                break;
        default:
                log_link_warning(link, "IPv4 link-local unknown event: %d", event);
                break;
        }
}

int ipv4ll_configure(Link *link) {
        uint64_t seed;
        int r;

        assert(link);
        assert(link->network);
        assert(link->network->link_local & ADDRESS_FAMILY_IPV4);

        if (!link->ipv4ll) {
                r = sd_ipv4ll_new(&link->ipv4ll);
                if (r < 0)
                        return r;
        }

        if (link->sd_device && net_get_unique_predictable_data(link->sd_device, &seed) >= 0) {
                r = sd_ipv4ll_set_address_seed(link->ipv4ll, seed);
                if (r < 0)
                        return r;
        }

        r = sd_ipv4ll_attach_event(link->ipv4ll, NULL, 0);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_mac(link->ipv4ll, &link->mac);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_ifindex(link->ipv4ll, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_callback(link->ipv4ll, ipv4ll_handler, link);
        if (r < 0)
                return r;

        return 0;
}
