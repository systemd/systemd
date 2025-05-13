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

/* When func() doesn't return the appropriate type, set variable to empty afterwards.
 * The func() may be provided by a dynamically loaded shared library, hence add an assertion. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)     \
        static inline void func##p(type *p) {                   \
                if (*p != (empty)) {                            \
                        DISABLE_WARNING_ADDRESS;                \
                        assert(func);                           \
                        REENABLE_WARNING;                       \
                        func(*p);                               \
                        *p = (empty);                           \
                }                                               \
        }

/* When func() doesn't return the appropriate type, and is also a macro, set variable to empty afterwards. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(type, func, empty)       \
        static inline void func##p(type *p) {                           \
                if (*p != (empty)) {                                    \
                        func(*p);                                       \
                        *p = (empty);                                   \
                }                                                       \
        }
