/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "errno-util.h"

int plymouth_connect(int flags);
int plymouth_send_raw(const void *raw, size_t size, int flags);

static inline bool ERRNO_IS_NO_PLYMOUTH(int r) {
        return IN_SET(abs(r), EAGAIN, ENOENT) || ERRNO_IS_DISCONNECT(r);
}
