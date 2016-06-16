/***
    This file is part of systemd.

    Copyright 2016 Andreas Rammhold <andreas@rammhold.de>

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

#include "sd-netlink.h"
#include "missing.h"
#include "networkd-netdev-vrf.h"

static int netdev_vrf_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Vrf *v;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        v = VRF(netdev);

        assert(v);

        r = sd_netlink_message_append_u32(m, IFLA_VRF_TABLE, v->table_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IPLA_VRF_TABLE attribute: %m");

        return r;
}

const NetDevVTable vrf_vtable = {
        .object_size = sizeof(Vrf),
        .sections = "NetDev\0VRF\0",
        .fill_message_create = netdev_vrf_fill_message_create,
        .create_type = NETDEV_CREATE_MASTER,
};
