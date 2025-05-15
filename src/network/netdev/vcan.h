/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/can/netlink.h>
#include <netinet/in.h>

#include "netdev.h"

typedef struct VCan {
        NetDev meta;
} VCan;

DEFINE_NETDEV_CAST(VCAN, VCan);

extern const NetDevVTable vcan_vtable;
