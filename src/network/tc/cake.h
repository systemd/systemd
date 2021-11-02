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

typedef struct CommonApplicationsKeptEnhanced {
        QDisc meta;

        /* Shaper parameters */
        int autorate;
        uint64_t bandwidth;

        /* Overhead compensation parameters */
        bool overhead_set;
        int overhead;
        CakeCompensationMode compensation_mode;

} CommonApplicationsKeptEnhanced;

DEFINE_QDISC_CAST(CAKE, CommonApplicationsKeptEnhanced);
extern const QDiscVTable cake_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_cake_bandwidth);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_overhead);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_tristate);
CONFIG_PARSER_PROTOTYPE(config_parse_cake_compensation_mode);
