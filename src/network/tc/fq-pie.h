/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct FlowQueuePIE {
        QDisc meta;

        uint32_t packet_limit;
} FlowQueuePIE;

DEFINE_QDISC_CAST(FQ_PIE, FlowQueuePIE);
extern const QDiscVTable fq_pie_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_fq_pie_packet_limit);
