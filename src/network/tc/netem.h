/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "networkd-link.h"
#include "time-util.h"

typedef struct QDiscs QDiscs;

typedef struct NetworkEmulator {
        usec_t delay;
        usec_t jitter;

        uint32_t limit;
        uint32_t loss;
        uint32_t duplicate;
} NetworkEmulator;

int network_emulator_new(NetworkEmulator **ret);
int network_emulator_fill_message(Link *link, QDiscs *qdisc, sd_netlink_message *req);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_network_emulator_delay);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_network_emulator_rate);
CONFIG_PARSER_PROTOTYPE(config_parse_tc_network_emulator_packet_limit);
