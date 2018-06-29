/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "netdev/netdev.h"

typedef struct Bridge {
        NetDev meta;

        int mcast_querier;
        int mcast_snooping;
        int vlan_filtering;
        int stp;
        uint16_t priority;
        uint16_t group_fwd_mask;
        uint16_t default_pvid;

        usec_t forward_delay;
        usec_t hello_time;
        usec_t max_age;
        usec_t ageing_time;
} Bridge;

DEFINE_NETDEV_CAST(BRIDGE, Bridge);
extern const NetDevVTable bridge_vtable;
