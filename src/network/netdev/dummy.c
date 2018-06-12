/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Susant Sahani <susant@redhat.com>
  Copyright © 2014 Tom Gundersen
***/

#include "netdev/dummy.h"

const NetDevVTable dummy_vtable = {
        .object_size = sizeof(Dummy),
        .sections = "Match\0NetDev\0",
        .create_type = NETDEV_CREATE_INDEPENDENT,
};
