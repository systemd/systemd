/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct VCan VCan;

#include <netinet/in.h>
#include <linux/can/netlink.h>

#include "netdev.h"

struct VCan {
        NetDev meta;
};

DEFINE_NETDEV_CAST(VCAN, VCan);

extern const NetDevVTable vcan_vtable;
