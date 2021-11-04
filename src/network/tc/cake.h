/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include <linux/pkt_sched.h>

#include "conf-parser.h"
#include "qdisc.h"

typedef enum CakeCompensationMode {
        CAKE_COMPENSATION_MODE_NONE = CAKE_ATM_NONE,
        CAKE_COMPENSATION_MODE_ATM  = CAKE_ATM_ATM,
        CAKE_COMPENSATION_MODE_PTM  = CAKE_ATM_PTM,
        _CAKE_COMPENSATION_MODE_MAX,
        _CAKE_COMPENSATION_MODE_INVALID = -EINVAL,
} CakeCompensationMode;

typedef enum CakeFlowIsolationMode {
        CAKE_FLOW_ISOLATION_MODE_NONE     = CAKE_FLOW_NONE,
        CAKE_FLOW_ISOLATION_MODE_SRC_IP   = CAKE_FLOW_SRC_IP,
        CAKE_FLOW_ISOLATION_MODE_DST_IP   = CAKE_FLOW_DST_IP,
        CAKE_FLOW_ISOLATION_MODE_HOSTS    = CAKE_FLOW_HOSTS,
        CAKE_FLOW_ISOLATION_MODE_FLOWS    = CAKE_FLOW_FLOWS,
        CAKE_FLOW_ISOLATION_MODE_DUAL_SRC = CAKE_FLOW_DUAL_SRC,
        CAKE_FLOW_ISOLATION_MODE_DUAL_DST = CAKE_FLOW_DUAL_DST,
        CAKE_FLOW_ISOLATION_MODE_TRIPLE   = CAKE_FLOW_TRIPLE,
        _CAKE_FLOW_ISOLATION_MODE_MAX,
        _CAKE_FLOW_ISOLATION_MODE_INVALID = -EINVAL,
} CakeFlowIsolationMode;

typedef enum CakePriorityQueueingPreset {
        CAKE_PRESET_DIFFSERV3  = CAKE_DIFFSERV_DIFFSERV3,
        CAKE_PRESET_DIFFSERV4  = CAKE_DIFFSERV_DIFFSERV4,
        CAKE_PRESET_DIFFSERV8  = CAKE_DIFFSERV_DIFFSERV8,
        CAKE_PRESET_BESTEFFORT = CAKE_DIFFSERV_BESTEFFORT,
        CAKE_PRESET_PRECEDENCE = CAKE_DIFFSERV_PRECEDENCE,
        _CAKE_PRESET_MAX,
        _CAKE_PRESET_INVALID = -EINVAL,
} CakePriorityQueueingPreset;

typedef struct CommonApplicationsKeptEnhanced {
        QDisc meta;

        /* Shaper parameters */
        int autorate;
        uint64_t bandwidth;

        /* Overhead compensation parameters */
        bool overhead_set;
        int overhead;
        uint32_t mpu;
        CakeCompensationMode compensation_mode;
        int raw;

        /* Flow isolation parameters */
        CakeFlowIsolationMode flow_isolation_mode;
        int nat;

        /* Priority queue parameters */
        CakePriorityQueueingPreset preset;
        uint32_t fwmark;

        /* Other parameters */
        int wash;
        int split_gso;

} CommonApplicationsKeptEnhanced;

DEFINE_QDISC_CAST(CAKE, CommonApplicationsKeptEnhanced);
extern const QDiscVTable cake_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_cake_bandwidth);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_overhead);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_mpu);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_tristate);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_compensation_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_flow_isolation_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_priority_queueing_preset);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_fwmark);
