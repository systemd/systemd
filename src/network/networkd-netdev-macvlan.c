/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "networkd-netdev-macvlan.h"
#include "conf-parser.h"

static const char* const macvlan_mode_table[_NETDEV_MACVLAN_MODE_MAX] = {
        [NETDEV_MACVLAN_MODE_PRIVATE] = "private",
        [NETDEV_MACVLAN_MODE_VEPA] = "vepa",
        [NETDEV_MACVLAN_MODE_BRIDGE] = "bridge",
        [NETDEV_MACVLAN_MODE_PASSTHRU] = "passthru",
};

DEFINE_STRING_TABLE_LOOKUP(macvlan_mode, MacVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_macvlan_mode, macvlan_mode, MacVlanMode, "Failed to parse macvlan mode");

static int netdev_macvlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        MacVlan *m;
        int r;

        assert(netdev);
        assert(link);
        assert(netdev->ifname);

        if (netdev->kind == NETDEV_KIND_MACVLAN)
                m = MACVLAN(netdev);
        else
                m = MACVTAP(netdev);

        assert(m);

        if (m->mode != _NETDEV_MACVLAN_MODE_INVALID) {
                r = sd_netlink_message_append_u32(req, IFLA_MACVLAN_MODE, m->mode);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_MACVLAN_MODE attribute: %m");
        }

        return 0;
}

static void macvlan_init(NetDev *n) {
        MacVlan *m;

        assert(n);

        if (n->kind == NETDEV_KIND_MACVLAN)
                m = MACVLAN(n);
        else
                m = MACVTAP(n);

        assert(m);

        m->mode = _NETDEV_MACVLAN_MODE_INVALID;
}

const NetDevVTable macvtap_vtable = {
        .object_size = sizeof(MacVlan),
        .init = macvlan_init,
        .sections = "Match\0NetDev\0MACVTAP\0",
        .fill_message_create = netdev_macvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
};

const NetDevVTable macvlan_vtable = {
        .object_size = sizeof(MacVlan),
        .init = macvlan_init,
        .sections = "Match\0NetDev\0MACVLAN\0",
        .fill_message_create = netdev_macvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
};
