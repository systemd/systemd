/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "qdisc.h"

typedef struct ClassfulMultiQueueing {
        QDisc meta;
} ClassfulMultiQueueing;

DEFINE_QDISC_CAST(MQ, ClassfulMultiQueueing);
extern const QDiscVTable mq_vtable;
