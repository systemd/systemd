/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Susant Sahani
***/

typedef struct VCan VCan;

#include <linux/can/netlink.h>

#include "netdev/netdev.h"

struct VCan {
        NetDev meta;
};

DEFINE_NETDEV_CAST(VCAN, VCan);

extern const NetDevVTable vcan_vtable;
