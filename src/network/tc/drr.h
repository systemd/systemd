/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct DeficitRoundRobinScheduler {
        QDisc meta;

        uint32_t quantum;
} DeficitRoundRobinScheduler;

DEFINE_QDISC_CAST(DRR, DeficitRoundRobinScheduler);
extern const QDiscVTable drr_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_drr_size);
