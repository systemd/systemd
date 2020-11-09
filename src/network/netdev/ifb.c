/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include "ifb.h"

const NetDevVTable ifb_vtable = {
        .object_size = sizeof(IntermediateFunctionalBlock),
        .sections = NETDEV_COMMON_SECTIONS,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .generate_mac = true,
};
