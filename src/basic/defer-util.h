/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"
#include "macro.h"

typedef void (*void_func_t)(void);

static inline void dispatch_void_func(void_func_t *f) {
        assert(f);
        assert(*f);
        (*f)();
}

/* Inspired by Go's "defer" construct, but much more basic. This basically just calls a void function when
 * the current scope is left. Doesn't do function parameters (i.e. no closures). */
#define DEFER_VOID_CALL(x) _DEFER_VOID_CALL(UNIQ, x)
#define _DEFER_VOID_CALL(uniq, x) _unused_ _cleanup_(dispatch_void_func) void_func_t UNIQ_T(defer, uniq) = (x)
