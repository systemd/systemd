/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013-2015 Tom Gundersen <teg@jklm.no>

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

#include <net/if.h>

#include "networkd-netdev-ipvlan.h"
#include "conf-parser.h"

static const char* const ipvlan_mode_table[_NETDEV_IPVLAN_MODE_MAX] = {
        [NETDEV_IPVLAN_MODE_L2] = "L2",
        [NETDEV_IPVLAN_MODE_L3] = "L3",
};

DEFINE_STRING_TABLE_LOOKUP(ipvlan_mode, IPVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipvlan_mode, ipvlan_mode, IPVlanMode, "Failed to parse ipvlan mode");

static int netdev_ipvlan_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *req) {
        IPVlan *m = IPVLAN(netdev);
        int r;

        assert(netdev);
        assert(m);
        assert(link);
        assert(netdev->ifname);

        if (m->mode != _NETDEV_IPVLAN_MODE_INVALID) {
        r = sd_rtnl_message_append_u16(req, IFLA_IPVLAN_MODE, m->mode);
        if (r < 0) {
                log_netdev_error(netdev,
                                 "Could not append IFLA_IPVLAN_MODE attribute: %s",
                                 strerror(-r));
                        return r;
                }
        }

        return 0;
}

static void ipvlan_init(NetDev *n) {
        IPVlan *m = IPVLAN(n);

        assert(n);
        assert(m);

        m->mode = _NETDEV_IPVLAN_MODE_INVALID;
}

const NetDevVTable ipvlan_vtable = {
        .object_size = sizeof(IPVlan),
        .init = ipvlan_init,
        .sections = "Match\0NetDev\0IPVLAN\0",
        .fill_message_create = netdev_ipvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
};
