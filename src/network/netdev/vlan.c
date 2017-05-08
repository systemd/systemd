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

#include <linux/if_vlan.h>
#include <net/if.h>

#include "netdev/vlan.h"
#include "vlan-util.h"

static int netdev_vlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        struct ifla_vlan_flags flags = {};
        VLan *v;
        int r;

        assert(netdev);
        assert(link);
        assert(req);

        v = VLAN(netdev);

        assert(v);

        r = sd_netlink_message_append_u16(req, IFLA_VLAN_ID, v->id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_VLAN_ID attribute: %m");

        if (v->gvrp != -1) {
                flags.mask |= VLAN_FLAG_GVRP;
                SET_FLAG(flags.flags, VLAN_FLAG_GVRP, v->gvrp);
        }

        if (v->mvrp != -1) {
                flags.mask |= VLAN_FLAG_MVRP;
                SET_FLAG(flags.flags, VLAN_FLAG_MVRP, v->mvrp);
        }

        if (v->reorder_hdr != -1) {
                flags.mask |= VLAN_FLAG_REORDER_HDR;
                SET_FLAG(flags.flags, VLAN_FLAG_REORDER_HDR, v->reorder_hdr);
        }

        if (v->loose_binding != -1) {
                flags.mask |= VLAN_FLAG_LOOSE_BINDING;
                SET_FLAG(flags.flags, VLAN_FLAG_LOOSE_BINDING, v->loose_binding);
        }

        r = sd_netlink_message_append_data(req, IFLA_VLAN_FLAGS, &flags, sizeof(struct ifla_vlan_flags));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_VLAN_FLAGS attribute: %m");

        return 0;
}

static int netdev_vlan_verify(NetDev *netdev, const char *filename) {
        VLan *v;

        assert(netdev);
        assert(filename);

        v = VLAN(netdev);

        assert(v);

        if (v->id == VLANID_INVALID) {
                log_warning("VLAN without valid Id (%"PRIu16") configured in %s.", v->id, filename);
                return -EINVAL;
        }

        return 0;
}

static void vlan_init(NetDev *netdev) {
        VLan *v = VLAN(netdev);

        assert(netdev);
        assert(v);

        v->id = VLANID_INVALID;
        v->gvrp = -1;
        v->mvrp = -1;
        v->loose_binding = -1;
        v->reorder_hdr = -1;
}

const NetDevVTable vlan_vtable = {
        .object_size = sizeof(VLan),
        .init = vlan_init,
        .sections = "Match\0NetDev\0VLAN\0",
        .fill_message_create = netdev_vlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_vlan_verify,
};
