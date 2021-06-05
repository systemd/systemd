/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"

typedef struct Xfrm {
        NetDev meta;

        uint32_t if_id;
        bool independent;
} Xfrm;

DEFINE_NETDEV_CAST(XFRM, Xfrm);
extern const NetDevVTable xfrm_vtable;
