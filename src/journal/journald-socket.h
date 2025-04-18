/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "time-util.h"

typedef struct Server Server;

int server_forward_socket(Server *s, const struct iovec *iovec, size_t n, const dual_timestamp *ts, int priority);
