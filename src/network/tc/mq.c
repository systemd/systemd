/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mq.h"

const QDiscVTable mq_vtable = {
        .object_size = sizeof(MultiQueueing),
        .tca_kind = "mq",
};
