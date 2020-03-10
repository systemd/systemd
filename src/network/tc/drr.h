/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "qdisc.h"

typedef struct DeficitRoundRobinScheduler {
        QDisc meta;
} DeficitRoundRobinScheduler;

DEFINE_QDISC_CAST(DRR, DeficitRoundRobinScheduler);
extern const QDiscVTable drr_vtable;
