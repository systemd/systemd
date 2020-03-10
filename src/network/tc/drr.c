/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc. */

#include "drr.h"

const QDiscVTable drr_vtable = {
        .object_size = sizeof(DeficitRoundRobinScheduler),
        .tca_kind = "drr",
};
