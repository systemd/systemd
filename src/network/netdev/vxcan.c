/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/can/vxcan.h>
#include <linux/if_arp.h>

#include "vxcan.h"

static int netdev_vxcan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(!link);
        assert(m);

        VxCan *v = VXCAN(netdev);
        int r;

        r = sd_netlink_message_open_container(m, VXCAN_INFO_PEER);
        if (r < 0)
                return r;

        if (v->ifname_peer) {
                r = sd_netlink_message_append_string(m, IFLA_IFNAME, v->ifname_peer);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_vxcan_verify(NetDev *netdev, const char *filename) {
        assert(filename);

        VxCan *v = VXCAN(netdev);

        if (!v->ifname_peer)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "VxCan NetDev without peer name configured in %s. Ignoring", filename);

        if (streq(v->ifname_peer, netdev->ifname))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "VxCan peer name cannot be the same as the main interface name.");

        return 0;
}

static int netdev_vxcan_attach(NetDev *netdev) {
        VxCan *v = VXCAN(netdev);
        assert(v->ifname_peer);

        return netdev_attach_name(netdev, v->ifname_peer);
}

static void netdev_vxcan_detach(NetDev *netdev) {
        VxCan *v = VXCAN(netdev);

        netdev_detach_name(netdev, v->ifname_peer);
}

static int netdev_vxcan_set_ifindex(NetDev *netdev, const char *name, int ifindex) {
        VxCan *v = VXCAN(netdev);
        int r;

        assert(name);
        assert(ifindex > 0);

        if (streq(netdev->ifname, name)) {
                r = netdev_set_ifindex_internal(netdev, ifindex);
                if (r <= 0)
                        return r;

        } else if (streq(v->ifname_peer, name)) {
                if (v->ifindex_peer == ifindex)
                        return 0; /* already set */
                if (v->ifindex_peer > 0 && v->ifindex_peer != ifindex)
                        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EEXIST),
                                                        "Could not set ifindex %i for peer %s, already set to %i.",
                                                        ifindex, v->ifname_peer, v->ifindex_peer);

                v->ifindex_peer = ifindex;
                log_netdev_debug(netdev, "Peer interface %s gained index %i.", v->ifname_peer, ifindex);

        } else
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (ifindex=%i).",
                                                name, ifindex);

        if (netdev->ifindex > 0 && v->ifindex_peer > 0)
                return netdev_enter_ready(netdev);

        return 0;
}

static int netdev_vxcan_get_ifindex(NetDev *netdev, const char *name) {
        VxCan *v = VXCAN(netdev);

        assert(name);

        if (streq(netdev->ifname, name))
                return netdev->ifindex;

        if (streq(v->ifname_peer, name))
                return v->ifindex_peer;

        return -ENODEV;
}

static void vxcan_done(NetDev *netdev) {
        VxCan *v = VXCAN(netdev);

        free(v->ifname_peer);
}

const NetDevVTable vxcan_vtable = {
        .object_size = sizeof(VxCan),
        .sections = NETDEV_COMMON_SECTIONS "VXCAN\0",
        .done = vxcan_done,
        .fill_message_create = netdev_vxcan_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_vxcan_verify,
        .attach = netdev_vxcan_attach,
        .detach = netdev_vxcan_detach,
        .set_ifindex = netdev_vxcan_set_ifindex,
        .get_ifindex = netdev_vxcan_get_ifindex,
        .iftype = ARPHRD_CAN,
        .keep_existing = true,
};
