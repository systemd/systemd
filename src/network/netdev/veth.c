/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <net/if.h>
#include <linux/veth.h>

#include "veth.h"

static int netdev_veth_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Veth *v;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        v = VETH(netdev);

        assert(v);

        r = sd_netlink_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append VETH_INFO_PEER attribute: %m");

        if (v->ifname_peer) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, v->ifname_peer);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Failed to add netlink interface name: %m");
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
        Veth *v;
        int r;

        assert(netdev);
        assert(filename);

        v = VETH(netdev);

        assert(v);

        if (!v->ifname_peer) {
                log_netdev_warning(netdev, "Veth NetDev without peer name configured in %s. Ignoring",
                                   filename);
                return -EINVAL;
        }

        if (!v->mac_peer) {
                r = netdev_get_mac(v->ifname_peer, &v->mac_peer);
                if (r < 0) {
                        log_netdev_warning(netdev,
                                           "Failed to generate predictable MAC address for %s. Ignoring",
                                           v->ifname_peer);
                        return -EINVAL;
                }
        }

        return 0;
}

static void veth_done(NetDev *n) {
        Veth *v;

        assert(n);

        v = VETH(n);

        assert(v);

        free(v->ifname_peer);
        free(v->mac_peer);
}

const NetDevVTable veth_vtable = {
        .object_size = sizeof(Veth),
        .sections = NETDEV_COMMON_SECTIONS "Peer\0",
        .done = veth_done,
        .fill_message_create = netdev_veth_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_veth_verify,
        .generate_mac = true,
};
