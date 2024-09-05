/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "missing_arphrd.h"
#include "vcan.h"

const NetDevVTable vcan_vtable = {
        .object_size = sizeof(VCan),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_CAN,
};
