/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct FairQueueTrafficPolicing {
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
} FairQueueTrafficPolicing;

DEFINE_QDISC_CAST(FQ, FairQueueTrafficPolicing);
extern const QDiscVTable fq_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_size);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_usec);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_max_rate);
