/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "missing_network.h"
#include "xfrm.h"

static int xfrm_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *message) {
        Xfrm *x;
        int r;

        assert(netdev);
        assert(message);

        x = XFRM(netdev);

        assert(x);
        assert(link || x->independent);

        r = sd_netlink_message_append_u32(message, IFLA_XFRM_LINK, link ? link->ifindex : LOOPBACK_IFINDEX);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(message, IFLA_XFRM_IF_ID, x->if_id);
        if (r < 0)
                return r;

        return 0;
}

static int xfrm_verify(NetDev *netdev, const char *filename) {
        Xfrm *x;

        assert(netdev);
        assert(filename);

        x = XFRM(netdev);

        assert(x);

        if (x->if_id == 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: Xfrm interface ID cannot be zero.", filename);

        return 0;
}

const NetDevVTable xfrm_vtable = {
        .object_size = sizeof(Xfrm),
        .sections = NETDEV_COMMON_SECTIONS "Xfrm\0",
        .fill_message_create = xfrm_fill_message_create,
        .config_verify = xfrm_verify,
        .create_type = NETDEV_CREATE_STACKED,
        .iftype = ARPHRD_NONE,
};
