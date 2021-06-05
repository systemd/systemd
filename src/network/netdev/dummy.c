/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dummy.h"

const NetDevVTable dummy_vtable = {
        .object_size = sizeof(Dummy),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .generate_mac = true,
};
