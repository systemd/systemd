/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "qdisc.h"

typedef struct BandMultiQueueing {
        QDisc meta;
} BandMultiQueueing;

DEFINE_QDISC_CAST(MULTIQ, BandMultiQueueing);
extern const QDiscVTable multiq_vtable;
