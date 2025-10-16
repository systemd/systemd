/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "shared-forward.h"
#include "qdisc.h"

typedef struct StochasticFairnessQueueing {
        QDisc meta;

        usec_t perturb_period;
} StochasticFairnessQueueing;

DEFINE_QDISC_CAST(SFQ, StochasticFairnessQueueing);
extern const QDiscVTable sfq_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_sfq_perturb_period);
