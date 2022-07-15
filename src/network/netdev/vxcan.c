/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/can/vxcan.h>
#include <linux/if_arp.h>

#include "vxcan.h"

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
        VxCan *v;

        assert(netdev);
        assert(filename);

        v = VXCAN(netdev);

        assert(v);

        if (!v->ifname_peer)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "VxCan NetDev without peer name configured in %s. Ignoring", filename);

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
        .sections = NETDEV_COMMON_SECTIONS "VXCAN\0",
        .done = vxcan_done,
        .fill_message_create = netdev_vxcan_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_vxcan_verify,
        .iftype = ARPHRD_CAN,
};
