/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "qdisc.h"

typedef struct MultiQueueing {
        QDisc meta;
} MultiQueueing;

DEFINE_QDISC_CAST(MULTIQ, MultiQueueing);
extern const QDiscVTable multiq_vtable;
