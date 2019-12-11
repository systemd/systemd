/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "networkd-link.h"

typedef struct StochasticFairnessQueueing {
        usec_t perturb_period;
} StochasticFairnessQueueing;

int stochastic_fairness_queueing_fill_message(Link *link, const StochasticFairnessQueueing *sfq, sd_netlink_message *req);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_stochastic_fairness_queueing_perturb_period);
