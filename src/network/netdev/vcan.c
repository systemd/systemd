/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Susant Sahani
***/

#include "netdev/vcan.h"

const NetDevVTable vcan_vtable = {
        .object_size = sizeof(VCan),
        .create_type = NETDEV_CREATE_INDEPENDENT,
};
