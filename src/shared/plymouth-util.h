/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "errno-util.h"
#include "forward.h"

int plymouth_connect(int flags);
int plymouth_send_raw(const void *raw, size_t size, int flags);
int plymouth_send_msg(const char *text, bool pause_spinner);
int plymouth_hide_splash(void);

static inline bool ERRNO_IS_NO_PLYMOUTH(int r) {
        return IN_SET(ABS(r), EAGAIN, ENOENT) || ERRNO_IS_DISCONNECT(r);
}
