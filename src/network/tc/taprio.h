/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 Intel Corporation */
#pragma once

#include <linux/pkt_sched.h>
#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"
#include "list.h"

typedef struct TimeAwarePrioShaper TimeAwarePrioShaper;
typedef struct sentry sentry;

struct sentry {
        TimeAwarePrioShaper *taprio;
        uint32_t index;
        uint32_t interval;
        uint32_t gatemask;
        uint8_t cmd;

        LIST_FIELDS(sentry, sched_entry);
};

struct TimeAwarePrioShaper {
        QDisc meta;

        LIST_HEAD(sentry, sched_head);
        unsigned n_entry;

        __s32 clockid;
        __u32 flags;
        __u32 txtime_delay;
        __s64 cycle_time;
        __s64 cycle_time_extension ;
        __s64 base_time;

        unsigned n_prio;
        uint8_t tc_num;
        uint8_t prio[MQ_PRIO_MAX + 1];
        unsigned n_queues;
        __u16 count[TC_QOPT_MAX_QUEUE];
        __u16 offset[TC_QOPT_MAX_QUEUE];

};

DEFINE_QDISC_CAST(TAPRIO, TimeAwarePrioShaper);
extern const QDiscVTable taprio_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_num_tc);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_priomap);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_queuemap);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_sched_entry);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_base_time);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_cycle_time);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_txtime_delay);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_clockid);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_taprio_flags);
