/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct ProportionalIntegralControllerEnhanced {
        QDisc meta;

        uint32_t packet_limit;
} ProportionalIntegralControllerEnhanced;

DEFINE_QDISC_CAST(PIE, ProportionalIntegralControllerEnhanced);
extern const QDiscVTable pie_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_pie_packet_limit);
