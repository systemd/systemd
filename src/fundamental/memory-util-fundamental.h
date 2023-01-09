/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

#ifdef SD_BOOT
#  include "efi-string.h"
#else
#  include <string.h>
#endif

#include "macro-fundamental.h"

#if defined(HAVE_EXPLICIT_BZERO)
static inline void *explicit_bzero_safe(void *p, size_t l) {
        if (p && l > 0)
                explicit_bzero(p, l);

        return p;
}
#else
static inline void *explicit_bzero_safe(void *p, size_t l) {
        if (p && l > 0) {
                memset(p, 0, l);
                __asm__ __volatile__("" : : "r"(p) : "memory");
        }
        return p;
}
#endif

struct VarEraser {
        void *p;
        size_t size;
};

static inline void erase_var(struct VarEraser *e) {
        explicit_bzero_safe(e->p, e->size);
}

/* Mark var to be erased when leaving scope. */
#define CLEANUP_ERASE(var) \
        _cleanup_(erase_var) _unused_ struct VarEraser CONCATENATE(_eraser_, UNIQ) = { .p = &var, .size = sizeof(var) }
