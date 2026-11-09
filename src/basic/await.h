/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

int fiber_ops_blocking_begin(void);
void fiber_ops_blocking_end(int *guard);

#define _SD_BLOCKING(expr, uniq) __extension__ ({                       \
        int UNIQ_T(_sd_blocking_guard_, uniq) __attribute__((cleanup(fiber_ops_blocking_end), unused)) = \
                fiber_ops_blocking_begin();                             \
        (expr);                                                         \
})

#define SD_BLOCKING(expr) _SD_BLOCKING(expr, UNIQ)
