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

static void ndisc_router_handler(sd_ndisc *nd, uint8_t flags, const struct in6_addr *gateway, unsigned lifetime, int pref, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        if (flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER)) {
                if (flags & ND_RA_FLAG_MANAGED)
                        dhcp6_request_address(link);

                r = sd_dhcp6_client_start(link->dhcp6_client);
                if (r < 0 && r != -EALREADY)
                        log_link_warning_errno(link, r, "Starting DHCPv6 client on NDisc request failed: %m");
        }
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
                if (r < 0 && r != -EALREADY)
                        log_link_warning_errno(link, r, "Starting DHCPv6 client after NDisc timeout failed: %m");
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
                                  NULL,
                                  NULL,
                                  ndisc_handler,
                                  link);

        return r;
}
