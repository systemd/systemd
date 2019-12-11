/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct FairQueueTrafficPolicing {
        QDisc meta;

        uint32_t limit;
} FairQueueTrafficPolicing;

DEFINE_QDISC_CAST(FQ, FairQueueTrafficPolicing);
extern const QDiscVTable fq_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_tc_fair_queue_traffic_policing_packet_limit);
