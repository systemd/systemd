/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

int manager_forward_socket(Manager *m, const struct iovec *iovec, size_t n, const dual_timestamp *ts, int priority);
void manager_reload_forward_socket(Manager *m, const SocketAddress *old);
