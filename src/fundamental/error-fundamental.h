/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"

/* MAX_ERRNO is defined as 4095 in linux/err.h. We use the same value here. */
#define ERRNO_MAX 4095

/* Error pointer functions — inspired by Linux kernel's ERR_PTR.
 *
 * Encode errno values into pointers in [UINTPTR_MAX - ERRNO_MAX, UINTPTR_MAX - 1]. UINTPTR_MAX itself is
 * excluded (used as sentinel: STRV_IGNORE, variadic terminators, etc.). Accepts both positive and negative
 * errno values. */

/* Single-comparison guard for cleanup macros and mfree(). Unlike PTR_IS_ERR() this also covers UINTPTR_MAX
 * (== POINTER_MAX). We need this because PTR_IS_ERR() deliberately excludes UINTPTR_MAX from the error range
 * causing -Wfree-nonheap-object to complain about error pointers being able to reach cleanup macros. */
#define PTR_IS_DIRTY(ptr) ((uintptr_t) (ptr) >= UINTPTR_MAX - ERRNO_MAX)

static inline _warn_unused_result_ void *ERR_TO_PTR(int error) {
        error = ABS(error);
        assert_se(error > 0 && error <= ERRNO_MAX);
        return (void *) (UINTPTR_MAX - (uintptr_t) error);
}

static inline _warn_unused_result_ bool PTR_IS_ERR(const void *ptr) {
        return PTR_IS_DIRTY(ptr) && (uintptr_t) ptr < UINTPTR_MAX;
}

static inline _warn_unused_result_ int PTR_TO_ERR(const void *ptr) {
        assert_se(PTR_IS_ERR(ptr));
        return -(int) (UINTPTR_MAX - (uintptr_t) ptr);
}

static inline _warn_unused_result_ bool PTR_IS_ERR_OR_NULL(const void *ptr) {
        return !ptr || PTR_IS_ERR(ptr);
}

static inline _warn_unused_result_ int PTR_TO_ERR_OR_ZERO(const void *ptr) {
        if (PTR_IS_ERR(ptr))
                return PTR_TO_ERR(ptr);
        return 0;
}
