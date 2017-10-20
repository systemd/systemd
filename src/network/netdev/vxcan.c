/***
  This file is part of systemd.

  Copyright 2017 Susant Sahani

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

#include "netdev/vxcan.h"
#include "missing.h"

static int netdev_vxcan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        VxCan *v;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        v = VXCAN(netdev);

        assert(v);

        r = sd_netlink_message_open_container(m, VXCAN_INFO_PEER);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append VXCAN_INFO_PEER attribute: %m");

        if (v->ifname_peer) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, v->ifname_peer);
                if (r < 0)
                        return log_error_errno(r, "Failed to add vxcan netlink interface peer name: %m");
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append VXCAN_INFO_PEER attribute: %m");

        return r;
}

static int netdev_vxcan_verify(NetDev *netdev, const char *filename) {
        VxCan *v;

        assert(netdev);
        assert(filename);

        v = VXCAN(netdev);

        assert(v);

        if (!v->ifname_peer) {
                log_warning("VxCan NetDev without peer name configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        return 0;
}

static void vxcan_done(NetDev *n) {
        VxCan *v;

        assert(n);

        v = VXCAN(n);

        assert(v);

        free(v->ifname_peer);
}

const NetDevVTable vxcan_vtable = {
        .object_size = sizeof(VxCan),
        .sections = "Match\0NetDev\0VXCAN\0",
        .done = vxcan_done,
        .fill_message_create = netdev_vxcan_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_vxcan_verify,
};
