/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "netdev/netdev.h"

typedef struct Dummy {
        NetDev meta;
} Dummy;

DEFINE_NETDEV_CAST(DUMMY, Dummy);
extern const NetDevVTable dummy_vtable;
