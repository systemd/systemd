/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "netdevsim.h"

const NetDevVTable netdevsim_vtable = {
        .object_size = sizeof(NetDevSim),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
