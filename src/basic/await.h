/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "../fundamental/await.h"

_sync_ int fiber_ops_blocking_begin(void);
_sync_ void fiber_ops_blocking_end(int *guard);

#define _SD_BLOCKING(expr, uniq) __extension__ ({                       \
        int _SD_SUSPEND_JOIN(_sd_blocking_guard_, uniq) __attribute__((cleanup(fiber_ops_blocking_end), unused)) \
                _SD_SUSPEND_ANNOTATE("sd:blocking_scope") = fiber_ops_blocking_begin(); \
        (expr);                                                          \
})

#define SD_BLOCKING(expr) _SD_BLOCKING(expr, __COUNTER__)
