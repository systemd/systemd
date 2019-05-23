/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "sd-netlink.h"
#include "missing.h"
#include "netdev/vrf.h"

static int netdev_vrf_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Vrf *v;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        v = VRF(netdev);

        assert(v);

        r = sd_netlink_message_append_u32(m, IFLA_VRF_TABLE, v->table);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IPLA_VRF_TABLE attribute: %m");

        return r;
}

const NetDevVTable vrf_vtable = {
        .object_size = sizeof(Vrf),
        .sections = "Match\0NetDev\0VRF\0",
        .fill_message_create = netdev_vrf_fill_message_create,
        .create_type = NETDEV_CREATE_MASTER,
        .generate_mac = true,
};
