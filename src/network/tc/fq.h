/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "shared-forward.h"
#include "qdisc.h"

typedef struct FairQueueing {
        QDisc meta;

        uint32_t packet_limit;
        uint32_t flow_limit;
        uint32_t quantum;
        uint32_t initial_quantum;
        uint32_t max_rate;
        uint32_t buckets;
        uint32_t orphan_mask;
        int pacing;
        usec_t ce_threshold_usec;
} FairQueueing;

DEFINE_QDISC_CAST(FQ, FairQueueing);
extern const QDiscVTable fq_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_fq_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_size);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_usec);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_max_rate);
