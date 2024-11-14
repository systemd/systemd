/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/if_arp.h>
#include <netinet/in.h>

#include "vrf.h"

static int netdev_vrf_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(!link);
        assert(m);

        Vrf *v = VRF(netdev);
        int r;

        r = sd_netlink_message_append_u32(m, IFLA_VRF_TABLE, v->table);
        if (r < 0)
                return r;

        return 0;
}

static bool vrf_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        return true;
}

const NetDevVTable vrf_vtable = {
        .object_size = sizeof(Vrf),
        .sections = NETDEV_COMMON_SECTIONS "VRF\0",
        .fill_message_create = netdev_vrf_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .can_set_mac = vrf_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .keep_existing = true,
};
