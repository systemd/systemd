/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

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

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "networkd-address.h"
#include "networkd-radv.h"
#include "sd-radv.h"

int radv_configure(Link *link) {
        int r;
        Prefix *p;

        assert(link);
        assert(link->network);

        r = sd_radv_new(&link->radv);
        if (r < 0)
                return r;

        r = sd_radv_attach_event(link->radv, NULL, 0);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->mac);
        if (r < 0)
                return r;

        r = sd_radv_set_ifindex(link->radv, link->ifindex);
        if (r < 0)
                return r;

        r = sd_radv_set_managed_information(link->radv, link->network->router_managed);
        if (r < 0)
                return r;

        r = sd_radv_set_other_information(link->radv, link->network->router_other_information);
        if (r < 0)
                return r;

        /* a value of 0xffffffff represents infinity, 0x0 means this host is
           not a router */
        r = sd_radv_set_router_lifetime(link->radv,
                                        DIV_ROUND_UP(link->network->router_lifetime_usec, USEC_PER_SEC));
        if (r < 0)
                return r;

        if (link->network->router_lifetime_usec > 0) {
                r = sd_radv_set_preference(link->radv,
                                           link->network->router_preference);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(prefixes, p, link->network->static_prefixes) {
                r = sd_radv_add_prefix(link->radv, p->radv_prefix);
                if (r != -EEXIST && r < 0)
                        return r;
        }

        return 0;
}
