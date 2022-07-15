/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct StochasticFairBlue {
        QDisc meta;

        uint32_t packet_limit;
} StochasticFairBlue;

DEFINE_QDISC_CAST(SFB, StochasticFairBlue);
extern const QDiscVTable sfb_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_stochastic_fair_blue_u32);
