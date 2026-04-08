/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"

/* A wrapper for 'func' to return void.
 * Only useful when a void-returning function is required by some API. */
#define DEFINE_TRIVIAL_DESTRUCTOR(name, type, func)     \
        static inline void name(type *p) {              \
                func(p);                                \
        }

/* When func() returns the void value (NULL, -1, …) of the appropriate type */
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)         \
        static inline void func##p(type *p) {           \
                if (*p)                                 \
                        *p = func(*p);                  \
        }

/* When func() doesn't return the appropriate type, set variable to empty afterwards. The func() may be
 * provided by a dynamically loaded (dlopen()) shared library, hence add an assertion. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(type, func, name, empty) \
        static inline void name(type *p) {                              \
                if (*p != (empty)) {                                    \
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
                if (*p != (empty)) {                                    \
                        macro(*p);                                      \
                        *p = (empty);                                   \
                }                                                       \
        }

#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(type, macro, empty)      \
        DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO_RENAME(type, macro, macro##p, empty)

/* Clean up an array by dropping all the items in it, up to the first empty item.
 * The array itself is not deallocated. */
#define DEFINE_ARRAY_DONE_FUNC(type, helper)                    \
        static inline void helper ## _many(type (*p)[]) {       \
                for (type *t = *ASSERT_PTR(p); *t; t++)         \
                        *t = helper(*t);                        \
        }

/* Clean up an array of pointers to objects by dropping all the items in it.
 * Then free the array itself. */
#define DEFINE_POINTER_ARRAY_FREE_FUNC(type, helper)            \
        void helper ## _array(type *array, size_t n) {          \
                assert(array || n == 0);                        \
                FOREACH_ARRAY(item, array, n)                   \
                        helper(*item);                          \
                free(array);                                    \
        }

/* Clean up an array of objects of known size by dropping all the items in it.
 * Then free the array itself. */
#define DEFINE_ARRAY_FREE_FUNC(name, type, helper)              \
        void name(type *array, size_t n) {                      \
                assert(array || n == 0);                        \
                FOREACH_ARRAY(item, array, n)                   \
                        helper(item);                           \
                free(array);                                    \
        }

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
