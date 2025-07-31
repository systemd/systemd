/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"

typedef struct VxCan {
        NetDev meta;

        char *ifname_peer;
        int ifindex_peer;
} VxCan;

DEFINE_NETDEV_CAST(VXCAN, VxCan);

extern const NetDevVTable vxcan_vtable;
