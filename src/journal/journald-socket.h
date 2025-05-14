/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "time-util.h"

typedef struct Manager Manager;

int manager_forward_socket(Manager *m, const struct iovec *iovec, size_t n, const dual_timestamp *ts, int priority);
