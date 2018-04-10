/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Andreas Rammhold <andreas@rammhold.de>
***/

typedef struct Vrf Vrf;

#include "netdev/netdev.h"

struct Vrf {
        NetDev meta;

        uint32_t table;
};

DEFINE_NETDEV_CAST(VRF, Vrf);
extern const NetDevVTable vrf_vtable;
