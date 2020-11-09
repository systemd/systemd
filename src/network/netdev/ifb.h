/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#pragma once

#include "netdev.h"

typedef struct IntermediateFunctionalBlock {
        NetDev meta;
} IntermediateFunctionalBlock;

DEFINE_NETDEV_CAST(IFB, IntermediateFunctionalBlock);
extern const NetDevVTable ifb_vtable;
