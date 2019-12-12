/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct FairQueuingControlledDelay {
        QDisc meta;
        uint32_t limit;
} FairQueuingControlledDelay;

DEFINE_QDISC_CAST(FQ_CODEL, FairQueuingControlledDelay);
extern const QDiscVTable fq_codel_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queuing_controlled_delay_limit);
