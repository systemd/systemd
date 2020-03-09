/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct proportional_integral_controller_enhanced {
        QDisc meta;

        uint32_t packet_limit;
} proportional_integral_controller_enhanced;

DEFINE_QDISC_CAST(PIE, proportional_integral_controller_enhanced);
extern const QDiscVTable pie_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_pie_packet_limit);
