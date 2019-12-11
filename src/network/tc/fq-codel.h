/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "networkd-link.h"

typedef struct FairQueuingControlledDelay {
        uint32_t limit;
} FairQueuingControlledDelay;

int fair_queuing_controlled_delay_fill_message(Link *link, const FairQueuingControlledDelay *sfq, sd_netlink_message *req);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queuing_controlled_delay_limit);
