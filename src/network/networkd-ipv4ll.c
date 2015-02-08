/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013-2014 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/ether.h>
#include <linux/if.h>

#include "networkd-link.h"
#include "network-internal.h"

static int ipv4ll_address_lost(Link *link) {
        _cleanup_address_free_ Address *address = NULL;
        _cleanup_route_free_ Route *route = NULL;
        struct in_addr addr;
        int r;

        assert(link);

        link->ipv4ll_route = false;
        link->ipv4ll_address =  false;

        r = sd_ipv4ll_get_address(link->ipv4ll, &addr);
        if (r < 0)
                return 0;

        log_link_debug(link, "IPv4 link-local release %u.%u.%u.%u", ADDRESS_FMT_VAL(addr));

        r = address_new_dynamic(&address);
        if (r < 0) {
                log_link_error(link, "Could not allocate address: %s", strerror(-r));
                return r;
        }

        address->family = AF_INET;
        address->in_addr.in = addr;
        address->prefixlen = 16;
        address->scope = RT_SCOPE_LINK;

        address_drop(address, link, &link_address_drop_handler);

        r = route_new_dynamic(&route, RTPROT_UNSPEC);
        if (r < 0) {
                log_link_error(link, "Could not allocate route: %s",
                               strerror(-r));
                return r;
        }

        route->family = AF_INET;
        route->scope = RT_SCOPE_LINK;
        route->metrics = IPV4LL_ROUTE_METRIC;

        route_drop(route, link, &link_route_drop_handler);

        link_client_handler(link);

        return 0;
}

static int ipv4ll_route_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(!link->ipv4ll_route);

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error(link, "could not set ipv4ll route: %s", strerror(-r));
                link_enter_failed(link);
        }

        link->ipv4ll_route = true;

        if (link->ipv4ll_address == true)
                link_client_handler(link);

        return 1;
}

static int ipv4ll_address_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(!link->ipv4ll_address);

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error(link, "could not set ipv4ll address: %s", strerror(-r));
                link_enter_failed(link);
        } else if (r >= 0)
                link_rtnl_process_address(rtnl, m, link->manager);

        link->ipv4ll_address = true;

        if (link->ipv4ll_route == true)
                link_client_handler(link);

        return 1;
}

static int ipv4ll_address_claimed(sd_ipv4ll *ll, Link *link) {
        _cleanup_address_free_ Address *ll_addr = NULL;
        _cleanup_route_free_ Route *route = NULL;
        struct in_addr address;
        int r;

        assert(ll);
        assert(link);

        r = sd_ipv4ll_get_address(ll, &address);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                return r;

        log_link_debug(link, "IPv4 link-local claim %u.%u.%u.%u",
                       ADDRESS_FMT_VAL(address));

        r = address_new_dynamic(&ll_addr);
        if (r < 0)
                return r;

        ll_addr->family = AF_INET;
        ll_addr->in_addr.in = address;
        ll_addr->prefixlen = 16;
        ll_addr->broadcast.s_addr = ll_addr->in_addr.in.s_addr | htonl(0xfffffffflu >> ll_addr->prefixlen);
        ll_addr->scope = RT_SCOPE_LINK;

        r = address_configure(ll_addr, link, ipv4ll_address_handler);
        if (r < 0)
                return r;

        link->ipv4ll_address = false;

        r = route_new_dynamic(&route, RTPROT_STATIC);
        if (r < 0)
                return r;

        route->family = AF_INET;
        route->scope = RT_SCOPE_LINK;
        route->metrics = IPV4LL_ROUTE_METRIC;

        r = route_configure(route, link, ipv4ll_route_handler);
        if (r < 0)
                return r;

        link->ipv4ll_route = false;

        return 0;
}

static void ipv4ll_handler(sd_ipv4ll *ll, int event, void *userdata){
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
                case IPV4LL_EVENT_STOP:
                case IPV4LL_EVENT_CONFLICT:
                        r = ipv4ll_address_lost(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        break;
                case IPV4LL_EVENT_BIND:
                        r = ipv4ll_address_claimed(ll, link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return;
                        }
                        break;
                default:
                        if (event < 0)
                                log_link_warning(link, "IPv4 link-local error: %s", strerror(-event));
                        else
                                log_link_warning(link, "IPv4 link-local unknown event: %d", event);
                        break;
        }
}

int ipv4ll_configure(Link *link) {
        uint8_t seed[8];
        int r;

        assert(link);
        assert(link->network);
        assert(IN_SET(link->network->link_local, ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_YES));

        r = sd_ipv4ll_new(&link->ipv4ll);
        if (r < 0)
                return r;

        if (link->udev_device) {
                r = net_get_unique_predictable_data(link->udev_device, seed);
                if (r >= 0) {
                        r = sd_ipv4ll_set_address_seed(link->ipv4ll, seed);
                        if (r < 0)
                                return r;
                }
        }

        r = sd_ipv4ll_attach_event(link->ipv4ll, NULL, 0);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_mac(link->ipv4ll, &link->mac);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_index(link->ipv4ll, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4ll_set_callback(link->ipv4ll, ipv4ll_handler, link);
        if (r < 0)
                return r;

        return 0;
}
