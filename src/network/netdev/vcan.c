/* SPDX-License-Identifier: LGPL-2.1+ */

#include "netdev/vcan.h"

const NetDevVTable vcan_vtable = {
        .object_size = sizeof(VCan),
        .sections = "Match\0NetDev\0",
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .generate_mac = true,
};
