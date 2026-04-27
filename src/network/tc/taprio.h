/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/pkt_sched.h>

#include "shared-forward.h"
#include "qdisc.h"

typedef struct TAPrioScheduleEntry {
        uint32_t command;    /* TC_TAPRIO_CMD_SET_GATES etc */
        uint32_t gate_mask;
        uint32_t interval;   /* in nanoseconds */
} TAPrioScheduleEntry;

typedef struct TimeAwarePriorityShaper {
        QDisc meta;

        uint32_t num_tc;
        uint8_t map[TC_QOPT_BITMASK + 1];  /* priority to TC mapping, 16 entries */
        uint16_t count[TC_QOPT_MAX_QUEUE];  /* queue count per TC */
        uint16_t offset[TC_QOPT_MAX_QUEUE]; /* queue offset per TC */
        int32_t clockid;          /* CLOCK_TAI, CLOCK_REALTIME, etc */
        int64_t base_time;        /* nanoseconds */
        int64_t cycle_time;       /* nanoseconds, 0 = unset */
        int64_t cycle_time_extension; /* nanoseconds, 0 = unset */
        uint32_t flags;           /* TAPRIO_FLAGS_* */

        TAPrioScheduleEntry *entries;
        size_t n_entries;
} TimeAwarePriorityShaper;

DEFINE_QDISC_CAST(TAPRIO, TimeAwarePriorityShaper);
extern const QDiscVTable taprio_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_taprio_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_clockid);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_schedule_entry);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_traffic_class_map);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_traffic_class_queues);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_base_time);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_cycle_time);
CONFIG_PARSER_PROTOTYPE(config_parse_taprio_flags);
