/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"
#include "error-fundamental.h"

DISABLE_WARNING_REDUNDANT_DECLS;
void free(void *p); /* NOLINT (readability-redundant-declaration) */
REENABLE_WARNING;

#define mfree(memory)                                   \
        ({                                              \
                typeof(memory) _mfree_ = (memory);      \
                if (!PTR_IS_DIRTY(_mfree_))             \
                        free(_mfree_);                  \
                (typeof(memory)) NULL;                  \
        })

/* A wrapper for 'func' to return void.
 * Only useful when a void-returning function is required by some API. */
#define DEFINE_TRIVIAL_DESTRUCTOR(name, type, func)     \
        static inline void name(type *p) {              \
                func(p);                                \
        }

/* When func() returns the void value (NULL, -1, …) of the appropriate type */
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)         \
        static inline void func##p(type *p) {           \
                if (*p && !PTR_IS_DIRTY(*p))            \
                        *p = func(*p);                  \
        }

/* When func() doesn't return the appropriate type, set variable to empty afterwards. The func() may be
 * provided by a dynamically loaded (dlopen()) shared library, hence add an assertion. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(type, func, name, empty) \
        static inline void name(type *p) {                              \
                if (*p != (empty) && !PTR_IS_DIRTY(*p)) {               \
                        DISABLE_WARNING_ADDRESS;                        \
                        assert(func);                                   \
                        REENABLE_WARNING;                               \
                        func(*p);                                       \
                        *p = (empty);                                   \
                }                                                       \
        }

#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)             \
        DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(type, func, func##p, empty)

/* When func() doesn't return the appropriate type, and is also a macro, set variable to empty afterwards. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO_RENAME(type, macro, name, empty) \
        static inline void name(type *p) {                              \
                if (*p != (empty) && !PTR_IS_DIRTY(*p)) {               \
                        macro(*p);                                      \
                        *p = (empty);                                   \
                }                                                       \
        }

#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(type, macro, empty)      \
        DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO_RENAME(type, macro, macro##p, empty)

typedef void (*free_array_func_t)(void *p, size_t n);

/* An automatic _cleanup_-like logic for destroy arrays (i.e. pointers + size) when leaving scope */
typedef struct ArrayCleanup {
        void **parray;
        size_t *pn;
        free_array_func_t pfunc;
} ArrayCleanup;

static inline void array_cleanup(const ArrayCleanup *c) {
        assert(c);
        assert(!c->parray == !c->pn);

        if (!c->parray)
                return;

        if (*c->parray) {
                assert(c->pfunc);
                c->pfunc(*c->parray, *c->pn);
                *c->parray = NULL;
        }

        *c->pn = 0;
}

#define CLEANUP_ARRAY(array, n, func)                                   \
        _cleanup_(array_cleanup) _unused_ const ArrayCleanup CONCATENATE(_cleanup_array_, UNIQ) = { \
                .parray = (void**) &(array),                            \
                .pn = &(n),                                             \
                .pfunc = (free_array_func_t) ({                         \
                                void (*_f)(typeof(array[0]) *a, size_t b) = func; \
                                _f;                                     \
                         }),                                            \
        }
