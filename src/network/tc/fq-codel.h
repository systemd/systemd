/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct FairQueueingControlledDelay {
        QDisc meta;

        uint32_t packet_limit;
        uint32_t flows;
        uint32_t quantum;
        uint32_t memory_limit;
        usec_t target_usec;
        usec_t interval_usec;
        usec_t ce_threshold_usec;
        int ecn;
} FairQueueingControlledDelay;

DEFINE_QDISC_CAST(FQ_CODEL, FairQueueingControlledDelay);
extern const QDiscVTable fq_codel_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_fair_queueing_controlled_delay_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_fair_queueing_controlled_delay_usec);
CONFIG_PARSER_PROTOTYPE(config_parse_fair_queueing_controlled_delay_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_fair_queueing_controlled_delay_size);
