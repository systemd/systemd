/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "qdisc.h"

typedef struct MultiQueueing {
        QDisc meta;
} MultiQueueing;

DEFINE_QDISC_CAST(MQ, MultiQueueing);
extern const QDiscVTable mq_vtable;
