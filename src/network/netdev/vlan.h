/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct VLan VLan;

#include "netdev/netdev.h"

struct VLan {
        NetDev meta;

        uint16_t id;

        int gvrp;
        int mvrp;
        int loose_binding;
        int reorder_hdr;
};

DEFINE_NETDEV_CAST(VLAN, VLan);
extern const NetDevVTable vlan_vtable;
