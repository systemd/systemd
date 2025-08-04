/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"

typedef struct NLMon {
        NetDev meta;
} NLMon;

DEFINE_NETDEV_CAST(NLMON, NLMon);

extern const NetDevVTable nlmon_vtable;
