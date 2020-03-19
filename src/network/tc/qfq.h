/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "qdisc.h"

typedef struct QuickFairQueueing {
        QDisc meta;
} QuickFairQueueing;

DEFINE_QDISC_CAST(QFQ, QuickFairQueueing);
extern const QDiscVTable qfq_vtable;
