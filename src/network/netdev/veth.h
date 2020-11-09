/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Veth Veth;

#include "netdev.h"

struct Veth {
        NetDev meta;

        char *ifname_peer;
        struct ether_addr *mac_peer;
};

DEFINE_NETDEV_CAST(VETH, Veth);
extern const NetDevVTable veth_vtable;
