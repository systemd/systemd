/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "netdevsim.h"

static bool netdevsim_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        return true;
}

const NetDevVTable netdevsim_vtable = {
        .object_size = sizeof(NetDevSim),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .can_set_mac = netdevsim_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
