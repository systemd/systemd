/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct VxCan VxCan;

#if HAVE_VXCAN_INFO_PEER
#include <linux/can/vxcan.h>
#endif

#include "netdev/netdev.h"

struct VxCan {
        NetDev meta;

        char *ifname_peer;
};

DEFINE_NETDEV_CAST(VXCAN, VxCan);

extern const NetDevVTable vxcan_vtable;
