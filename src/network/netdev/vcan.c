/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vcan.h"

#include <linux/if_arp.h>

const NetDevVTable vcan_vtable = {
        .object_size = sizeof(VCan),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_CAN,
};
