/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct TunTap TunTap;

#include "netdev/netdev.h"

struct TunTap {
        NetDev meta;

        char *user_name;
        char *group_name;
        bool multi_queue;
        bool packet_info;
        bool vnet_hdr;
};

DEFINE_NETDEV_CAST(TUN, TunTap);
DEFINE_NETDEV_CAST(TAP, TunTap);
extern const NetDevVTable tun_vtable;
extern const NetDevVTable tap_vtable;
