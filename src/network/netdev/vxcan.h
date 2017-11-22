#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Susant Sahani

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct VxCan VxCan;

#if HAVE_VXCAN_INFO_PEER
#include <linux/can/vxcan.h>
#endif

#include "netdev/netdev.h"

struct VxCan {
        NetDev meta;

        char *ifname_peer;
};

DEFINE_NETDEV_CAST(VXCAN, VxCan);

extern const NetDevVTable vxcan_vtable;
