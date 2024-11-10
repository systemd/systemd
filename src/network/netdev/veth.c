/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <errno.h>
#include <linux/if_arp.h>
#include <linux/veth.h>
#include <netinet/in.h>

#include "netlink-util.h"
#include "veth.h"

static int netdev_veth_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(!link);
        assert(m);

        struct hw_addr_data hw_addr;
        Veth *v = VETH(netdev);
        int r;

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
        assert(filename);

        Veth *v = VETH(netdev);

        if (!v->ifname_peer)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Veth NetDev without peer name configured in %s. Ignoring",
                                                filename);

        if (streq(v->ifname_peer, netdev->ifname))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Veth peer name cannot be the same as the main interface name.");

        return 0;
}

static int netdev_veth_attach(NetDev *netdev) {
        Veth *v = VETH(netdev);

        assert(v->ifname_peer);
        return netdev_attach_name(netdev, v->ifname_peer);
}

static void netdev_veth_detach(NetDev *netdev) {
        Veth *v = VETH(netdev);

        netdev_detach_name(netdev, v->ifname_peer);
}

static int netdev_veth_set_ifindex(NetDev *netdev, const char *name, int ifindex) {
        Veth *v = VETH(netdev);
        int r;

        assert(name);
        assert(ifindex > 0);

        if (streq(netdev->ifname, name)) {
                r = netdev_set_ifindex_internal(netdev, ifindex);
                if (r <= 0)
                        return r;

        } else if (streq(v->ifname_peer, name)) {
                if (v->ifindex_peer == ifindex)
                        return 0; /* already set. */

                if (v->ifindex_peer > 0 && v->ifindex_peer != ifindex)
                        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EEXIST),
                                                        "Could not set ifindex %i for peer %s, already set to %i.",
                                                        ifindex, v->ifname_peer, v->ifindex_peer);

                v->ifindex_peer = ifindex;
                log_netdev_debug(netdev, "Peer interface %s gained index %i.", v->ifname_peer, ifindex);

        } else
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (index=%i).",
                                                name, ifindex);

        if (netdev->ifindex > 0 && v->ifindex_peer > 0)
                return netdev_enter_ready(netdev);

        return 0;
}

static int netdev_veth_get_ifindex(NetDev *netdev, const char *name) {
        Veth *v = VETH(netdev);

        assert(name);

        if (streq(netdev->ifname, name))
                return netdev->ifindex;

        if (streq(v->ifname_peer, name))
                return v->ifindex_peer;

        return -ENODEV;
}

static void veth_done(NetDev *netdev) {
        Veth *v = VETH(netdev);

        free(v->ifname_peer);
}

const NetDevVTable veth_vtable = {
        .object_size = sizeof(Veth),
        .sections = NETDEV_COMMON_SECTIONS "Peer\0",
        .done = veth_done,
        .fill_message_create = netdev_veth_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_veth_verify,
        .attach = netdev_veth_attach,
        .detach = netdev_veth_detach,
        .set_ifindex = netdev_veth_set_ifindex,
        .get_ifindex = netdev_veth_get_ifindex,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .keep_existing = true,
};
