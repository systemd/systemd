/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */

#include "qdisc.h"
#include "qfq.h"

const QDiscVTable qfq_vtable = {
        .object_size = sizeof(QuickFairQueueing),
        .tca_kind = "qfq",
};
