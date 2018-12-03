#pragma once

#include "macro.h"

/* A framework for registering static variables that shall be freed on shutdown of a process. It's a bit like gcc's
 * destructor attribute, but allows us to precisely schedule when we want to free the variables. This is supposed to
 * feel a bit like the gcc cleanup attribute, but for static variables. Note that this does not work for static
 * variables declared in .so's, as the list is private to the same linking unit. But maybe that's a good thing. */

typedef struct StaticDestructor {
        void *data;
        void (*destroy)(void *p);
} StaticDestructor;

#define STATIC_DESTRUCTOR_REGISTER(variable, func) \
        _STATIC_DESTRUCTOR_REGISTER(UNIQ, variable, func)

#define _STATIC_DESTRUCTOR_REGISTER(uq, variable, func)                 \
        /* Type-safe destructor */                                      \
        static void UNIQ_T(static_destructor_wrapper, uq)(void *p) {    \
                typeof(variable) *q = p;                                \
                func(q);                                                \
        }                                                               \
        /* The actual destructor structure */                           \
        __attribute__ ((__section__("SYSTEMD_STATIC_DESTRUCT")))        \
        __attribute__ ((__aligned__(__BIGGEST_ALIGNMENT__)))            \
        __attribute__ ((__used__))                                      \
        static const StaticDestructor UNIQ_T(static_destructor_entry, uq) = { \
                .data = &(variable),                                    \
                .destroy = UNIQ_T(static_destructor_wrapper, uq),       \
        }

/* Beginning and end of our section listing the destructors. We define these as weak as we want this to work even if
 * there's not a single destructor is defined in which case the section will be missing. */
extern const struct StaticDestructor _weak_ __start_SYSTEMD_STATIC_DESTRUCT[];
extern const struct StaticDestructor _weak_ __stop_SYSTEMD_STATIC_DESTRUCT[];

/* The function to destroy everything. (Note that this must be static inline, as it's key that it remains in the same
 * linking unit as the variables we want to destroy. */
static inline void static_destruct(void) {
        const StaticDestructor *d;

        if (!__start_SYSTEMD_STATIC_DESTRUCT)
                return;

        d = ALIGN_TO_PTR(__start_SYSTEMD_STATIC_DESTRUCT, __BIGGEST_ALIGNMENT__);
        while (d < __stop_SYSTEMD_STATIC_DESTRUCT) {
                d->destroy(d->data);
                d = ALIGN_TO_PTR(d + 1, __BIGGEST_ALIGNMENT__);
        }
}
