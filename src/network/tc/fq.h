/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include <linux/pkt_sched.h>

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
        uint32_t low_rate_threshold;
        int pacing;
        usec_t ce_threshold_usec;
        usec_t timer_slack_usec;
        usec_t horizon_usec;
        usec_t offload_horizon_usec;
        int horizon_drop; /* tristate: -1 unset, 0 = cap, 1 = drop */
        uint8_t priomap[TC_PRIO_MAX + 1];
        unsigned n_priomap;
        int weights[FQ_BANDS];
        unsigned n_weights;
} FairQueueing;

DEFINE_QDISC_CAST(FQ, FairQueueing);
extern const QDiscVTable fq_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_fq_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_size);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_sec);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_max_rate);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_rate);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_priomap);
CONFIG_PARSER_PROTOTYPE(config_parse_fq_weights);
