/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "time-util.h"

typedef struct NetworkEmulator {
        QDisc meta;

        usec_t delay;
        usec_t jitter;

        uint32_t limit;
        uint32_t loss;
        uint32_t duplicate;
} NetworkEmulator;

DEFINE_QDISC_CAST(NETEM, NetworkEmulator);
extern const QDiscVTable netem_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_network_emulator_delay);
CONFIG_PARSER_PROTOTYPE(config_parse_network_emulator_rate);
CONFIG_PARSER_PROTOTYPE(config_parse_network_emulator_packet_limit);
