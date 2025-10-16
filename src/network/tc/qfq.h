/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "shared-forward.h"
#include "qdisc.h"
#include "tclass.h"

typedef struct QuickFairQueueing {
        QDisc meta;
} QuickFairQueueing;

DEFINE_QDISC_CAST(QFQ, QuickFairQueueing);
extern const QDiscVTable qfq_vtable;

typedef struct QuickFairQueueingClass {
        TClass meta;

        uint32_t weight;
        uint32_t max_packet;
} QuickFairQueueingClass;

DEFINE_TCLASS_CAST(QFQ, QuickFairQueueingClass);
extern const TClassVTable qfq_tclass_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_qfq_weight);
CONFIG_PARSER_PROTOTYPE(config_parse_qfq_max_packet);
