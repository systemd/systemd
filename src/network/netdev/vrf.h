/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Vrf Vrf;

#include "netdev.h"

struct Vrf {
        NetDev meta;

        uint32_t table;
};

DEFINE_NETDEV_CAST(VRF, Vrf);
extern const NetDevVTable vrf_vtable;
