/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct NLMon NLMon;

#include "netdev.h"

struct NLMon {
        NetDev meta;
};

DEFINE_NETDEV_CAST(NLMON, NLMon);

extern const NetDevVTable nlmon_vtable;
