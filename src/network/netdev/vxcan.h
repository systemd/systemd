/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct VxCan VxCan;

#include "netdev.h"

struct VxCan {
        NetDev meta;

        char *ifname_peer;
        int ifindex_peer;
};

DEFINE_NETDEV_CAST(VXCAN, VxCan);

extern const NetDevVTable vxcan_vtable;
