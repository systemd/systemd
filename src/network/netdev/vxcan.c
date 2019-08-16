/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/can/vxcan.h>

#include "netdev/vxcan.h"

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
        .generate_mac = true,
};
