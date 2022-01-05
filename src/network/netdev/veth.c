/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/veth.h>

#include "netlink-util.h"
#include "veth.h"

static int netdev_veth_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        struct hw_addr_data hw_addr;
        Veth *v;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        v = VETH(netdev);

        assert(v);

        r = sd_netlink_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return r;

        if (v->ifname_peer) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, v->ifname_peer);
                if (r < 0)
                        return r;
        }

        r = netdev_generate_hw_addr(netdev, NULL, v->ifname_peer, &v->hw_addr_peer, &hw_addr);
        if (r < 0)
                return r;

        if (hw_addr.length > 0) {
                log_netdev_debug(netdev, "Using MAC address for peer: %s", HW_ADDR_TO_STR(&hw_addr));
                r = netlink_message_append_hw_addr(m, IFLA_ADDRESS, &hw_addr);
                if (r < 0)
                        return r;
        }

        if (netdev->mtu != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_veth_verify(NetDev *netdev, const char *filename) {
        Veth *v;

        assert(netdev);
        assert(filename);

        v = VETH(netdev);

        assert(v);

        if (!v->ifname_peer)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Veth NetDev without peer name configured in %s. Ignoring",
                                                filename);

        return 0;
}

static void veth_done(NetDev *n) {
        Veth *v;

        assert(n);

        v = VETH(n);

        assert(v);

        free(v->ifname_peer);
}

const NetDevVTable veth_vtable = {
        .object_size = sizeof(Veth),
        .sections = NETDEV_COMMON_SECTIONS "Peer\0",
        .done = veth_done,
        .fill_message_create = netdev_veth_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_veth_verify,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
