/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mq.h"

const QDiscVTable mq_vtable = {
        .object_size = sizeof(ClassfulMultiQueueing),
        .tca_kind = "mq",
};
