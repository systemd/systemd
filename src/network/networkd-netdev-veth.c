/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani <susant@redhat.com>

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
#include <linux/veth.h>

#include "sd-netlink.h"
#include "networkd-netdev-veth.h"

static int netdev_veth_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Veth *v = VETH(netdev);
        int r;

        assert(netdev);
        assert(!link);
        assert(v);
        assert(m);

        r = sd_netlink_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append VETH_INFO_PEER attribute: %m");

        if (v->ifname_peer) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, v->ifname_peer);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface name: %m");
        }

        if (v->mac_peer) {
                r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, v->mac_peer);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_ADDRESS attribute: %m");
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        return r;
}

static int netdev_veth_verify(NetDev *netdev, const char *filename) {
        Veth *v = VETH(netdev);
        int r;

        assert(netdev);
        assert(v);
        assert(filename);

        if (!v->ifname_peer) {
                log_warning("Veth NetDev without peer name configured in %s. Ignoring",
                            filename);
                return -EINVAL;
        }

        if (!v->mac_peer) {
                r = netdev_get_mac(v->ifname_peer, &v->mac_peer);
                if (r < 0) {
                        log_warning("Failed to generate predictable MAC address for %s. Ignoring",
                                  v->ifname_peer);
                        return -EINVAL;
                }
        }

        return 0;
}

static void veth_done(NetDev *n) {
        Veth *v = VETH(n);

        assert(n);
        assert(v);

        free(v->ifname_peer);
        free(v->mac_peer);
}

const NetDevVTable veth_vtable = {
        .object_size = sizeof(Veth),
        .sections = "Match\0NetDev\0Peer\0",
        .done = veth_done,
        .fill_message_create = netdev_veth_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_veth_verify,
};
