/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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
#include <netinet/icmp6.h>
#include <linux/if.h>

#include "sd-ndisc.h"

#include "networkd-link.h"

static int ndisc_netlink_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_link_unref_ Link *link = userdata;
        int r;

        assert(link);
        assert(link->ndisc_messages > 0);

        link->ndisc_messages --;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not set NDisc route or address: %m");
                link_enter_failed(link);
        }

        if (link->ndisc_messages == 0) {
                link->ndisc_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static void ndisc_prefix_autonomous_handler(sd_ndisc *nd, const struct in6_addr *prefix, unsigned prefixlen,
                                            unsigned lifetime_preferred, unsigned lifetime_valid, void *userdata) {
        _cleanup_address_free_ Address *address = NULL;
        Link *link = userdata;
        usec_t time_now;
        int r;

        assert(nd);
        assert(link);
        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        r = address_new(&address);
        if (r < 0) {
                log_link_error_errno(link, r, "Could not allocate address: %m");
                return;
        }

        assert_se(sd_event_now(link->manager->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        address->family = AF_INET6;
        address->in_addr.in6 = *prefix;
        if (in_addr_is_null(AF_INET6, (const union in_addr_union *) &link->network->ipv6_token) == 0)
                memcpy(((char *)&address->in_addr.in6) + 8, ((char *)&link->network->ipv6_token) + 8, 8);
        else {
                /* see RFC4291 section 2.5.1 */
                address->in_addr.in6.__in6_u.__u6_addr8[8]  = link->mac.ether_addr_octet[0];
                address->in_addr.in6.__in6_u.__u6_addr8[8] ^= 1 << 1;
                address->in_addr.in6.__in6_u.__u6_addr8[9]  = link->mac.ether_addr_octet[1];
                address->in_addr.in6.__in6_u.__u6_addr8[10] = link->mac.ether_addr_octet[2];
                address->in_addr.in6.__in6_u.__u6_addr8[11] = 0xff;
                address->in_addr.in6.__in6_u.__u6_addr8[12] = 0xfe;
                address->in_addr.in6.__in6_u.__u6_addr8[13] = link->mac.ether_addr_octet[3];
                address->in_addr.in6.__in6_u.__u6_addr8[14] = link->mac.ether_addr_octet[4];
                address->in_addr.in6.__in6_u.__u6_addr8[15] = link->mac.ether_addr_octet[5];
        }
        address->prefixlen = prefixlen;
        address->flags = IFA_F_NOPREFIXROUTE;
        address->cinfo.ifa_prefered = lifetime_preferred;
        address->cinfo.ifa_valid = lifetime_valid;

        r = address_configure(address, link, ndisc_netlink_handler, true);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set SLAAC address: %m");
                link_enter_failed(link);
                return;
        }

        link->ndisc_messages ++;
}

static void ndisc_prefix_onlink_handler(sd_ndisc *nd, const struct in6_addr *prefix, unsigned prefixlen, unsigned lifetime, void *userdata) {
        _cleanup_route_free_ Route *route = NULL;
        Link *link = userdata;
        usec_t time_now;
        int r;

        assert(nd);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        r = route_new(&route);
        if (r < 0) {
                log_link_error_errno(link, r, "Could not allocate route: %m");
                return;
        }

        assert_se(sd_event_now(link->manager->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        route->family = AF_INET6;
        route->table = RT_TABLE_MAIN;
        route->protocol = RTPROT_RA;
        route->flags = RTM_F_PREFIX;
        route->dst.in6 = *prefix;
        route->dst_prefixlen = prefixlen;
        route->lifetime = time_now + lifetime * USEC_PER_SEC;

        r = route_configure(route, link, ndisc_netlink_handler);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set prefix route: %m");
                link_enter_failed(link);
                return;
        }

        link->ndisc_messages ++;
}

static void ndisc_router_handler(sd_ndisc *nd, uint8_t flags, const struct in6_addr *gateway, unsigned lifetime, int pref, void *userdata) {
        _cleanup_route_free_ Route *route = NULL;
        Link *link = userdata;
        usec_t time_now;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        if (flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER)) {
                if (flags & ND_RA_FLAG_MANAGED)
                        dhcp6_request_address(link);

                r = sd_dhcp6_client_start(link->dhcp6_client);
                if (r < 0 && r != -EBUSY)
                        log_link_warning_errno(link, r, "Starting DHCPv6 client on NDisc request failed: %m");
        }

        if (!gateway)
                return;

        r = route_new(&route);
        if (r < 0) {
                log_link_error_errno(link, r, "Could not allocate route: %m");
                return;
        }

        assert_se(sd_event_now(link->manager->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        route->family = AF_INET6;
        route->table = RT_TABLE_MAIN;
        route->protocol = RTPROT_RA;
        route->pref = pref;
        route->gw.in6 = *gateway;
        route->lifetime = time_now + lifetime * USEC_PER_SEC;

        r = route_configure(route, link, ndisc_netlink_handler);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set default route: %m");
                link_enter_failed(link);
                return;
        }

        link->ndisc_messages ++;
}

static void ndisc_handler(sd_ndisc *nd, int event, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
        case SD_NDISC_EVENT_TIMEOUT:
                dhcp6_request_address(link);

                r = sd_dhcp6_client_start(link->dhcp6_client);
                if (r < 0 && r != -EBUSY)
                        log_link_warning_errno(link, r, "Starting DHCPv6 client after NDisc timeout failed: %m");

                link->ndisc_configured = true;
                link_check_ready(link);

                break;
        case SD_NDISC_EVENT_STOP:
                break;
        default:
                log_link_warning(link, "IPv6 Neighbor Discovery unknown event: %d", event);
        }
}

int ndisc_configure(Link *link) {
        int r;

        assert_return(link, -EINVAL);

        r = sd_ndisc_new(&link->ndisc_router_discovery);
        if (r < 0)
                return r;

        r = sd_ndisc_attach_event(link->ndisc_router_discovery, NULL, 0);
        if (r < 0)
                return r;

        r = sd_ndisc_set_mac(link->ndisc_router_discovery, &link->mac);
        if (r < 0)
                return r;

        r = sd_ndisc_set_index(link->ndisc_router_discovery, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ndisc_set_callback(link->ndisc_router_discovery,
                                  ndisc_router_handler,
                                  ndisc_prefix_onlink_handler,
                                  ndisc_prefix_autonomous_handler,
                                  ndisc_handler,
                                  link);

        return r;
}
