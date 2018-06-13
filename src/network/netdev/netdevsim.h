/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2018 Susant Sahani
***/

typedef struct NetDevSim NetDevSim;

#include "netdev/netdev.h"

struct NetDevSim {
        NetDev meta;
};

DEFINE_NETDEV_CAST(NETDEVSIM, NetDevSim);
extern const NetDevVTable netdevsim_vtable;
