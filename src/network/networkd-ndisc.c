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
#include <linux/if.h>

#include "sd-ndisc.h"

#include "networkd-link.h"

static void ndisc_router_handler(sd_ndisc *nd, int event, void *userdata) {
        Link *link = userdata;

        assert(link);
        assert(link->network);
        assert(link->manager);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
        case SD_NDISC_EVENT_STOP:
        case SD_NDISC_EVENT_ROUTER_ADVERTISMENT_NONE:
                return;

        case SD_NDISC_EVENT_ROUTER_ADVERTISMENT_OTHER:
                dhcp6_configure(link, true);

                break;
        case SD_NDISC_EVENT_ROUTER_ADVERTISMENT_TIMEOUT:
        case SD_NDISC_EVENT_ROUTER_ADVERTISMENT_MANAGED:
                dhcp6_configure(link, false);

                break;

        default:
                log_link_warning(link, "IPv6 Neighbor Discovery unknown event: %d", event);

                break;
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
                                  ndisc_router_handler, link);

        return r;
}
