/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/pkt_sched.h>

#include "shared-forward.h"
#include "qdisc.h"

typedef struct MultiQueuePriorityQDisc {
        QDisc meta;

        uint8_t num_tc;
        uint8_t priority_map[TC_QOPT_BITMASK + 1];
        unsigned n_priority_map;
        uint16_t queue_count[TC_QOPT_MAX_QUEUE];
        uint16_t queue_offset[TC_QOPT_MAX_QUEUE];
        unsigned n_queues;
        uint8_t hw;
} MultiQueuePriorityQDisc;

DEFINE_QDISC_CAST(MQPRIO, MultiQueuePriorityQDisc);
extern const QDiscVTable mqprio_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_mqprio_num_tc);
CONFIG_PARSER_PROTOTYPE(config_parse_mqprio_priority_map);
CONFIG_PARSER_PROTOTYPE(config_parse_mqprio_queues);
CONFIG_PARSER_PROTOTYPE(config_parse_mqprio_hw);
