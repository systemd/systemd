/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "qdisc.h"

typedef struct DeficitRoundRobinScheduler {
        QDisc meta;
} DeficitRoundRobinScheduler;

DEFINE_QDISC_CAST(DRR, DeficitRoundRobinScheduler);
extern const QDiscVTable drr_vtable;

typedef struct DeficitRoundRobinSchedulerClass {
        TClass meta;

        uint32_t quantum;
} DeficitRoundRobinSchedulerClass;

DEFINE_TCLASS_CAST(DRR, DeficitRoundRobinSchedulerClass);
extern const TClassVTable drr_tclass_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_drr_size);
