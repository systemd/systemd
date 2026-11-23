/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <limits.h>

#include "../fundamental/assert-util.h"
#include "../fundamental/cleanup-util.h" /* IWYU pragma: export */

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

#define free_and_replace_full(a, b, free_func)  \
        ({                                      \
                typeof(a)* _a = &(a);           \
                typeof(b)* _b = &(b);           \
                free_func(*_a);                 \
                *_a = *_b;                      \
                *_b = NULL;                     \
                0;                              \
        })

/* This is similar to free_and_replace_full(), but NULL is not assigned to 'b', and its reference counter is
 * increased. */
#define unref_and_replace_new_ref(a, b, ref_func, unref_func) \
        ({                                                    \
                typeof(a)* _a = &(a);                         \
                typeof(b) _b = ref_func(b);                   \
                unref_func(*_a);                              \
                *_a = _b;                                     \
                0;                                            \
        })

static inline void ref_counter_inc(unsigned *n) {
        assert(n);

        /* Increases a reference counter, but refuses to let it overflow. Getting anywhere near UINT_MAX
         * references to a single object almost certainly means references are leaked somewhere (keeping
         * that many legitimate references around would require tens of GiB of memory just for the
         * pointers), i.e. it's a programming error, hence abort instead of returning an error. Note that we
         * use assert_se() here rather than assert(), so that this check is not compiled out with NDEBUG:
         * allowing the counter to wrap around would result in the object being freed while it is still
         * referenced, i.e. in a use-after-free. */
        assert_se(*n < UINT_MAX);
        (*n)++;
}

#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)                                     \
        scope type *name##_ref(type *p) {                                               \
                if (!p)                                                                 \
                        return NULL;                                                    \
                                                                                        \
                assert(p->n_ref > 0);                                                   \
                ref_counter_inc(&p->n_ref);                                             \
                return p;                                                               \
        }

#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope)                        \
        scope type *name##_unref(type *p) {                                             \
                if (!p)                                                                 \
                        return NULL;                                                    \
                                                                                        \
                assert(p->n_ref > 0);                                                   \
                p->n_ref--;                                                             \
                if (p->n_ref > 0)                                                       \
                        return NULL;                                                    \
                                                                                        \
                return free_func(p);                                                    \
        }

#define DEFINE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name,)
#define DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, static)
#define DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name)      \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, _public_)

#define DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func,)
#define DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, static)
#define DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func)         \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, _public_)

#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DECLARE_TRIVIAL_REF_FUNC(type, name) \
        type* name##_ref(type *p)

#define DECLARE_TRIVIAL_UNREF_FUNC(type, name) \
        type* name##_unref(type *p)

#define DECLARE_TRIVIAL_REF_UNREF_FUNC(type, name)      \
        DECLARE_TRIVIAL_REF_FUNC(type, name);           \
        DECLARE_TRIVIAL_UNREF_FUNC(type, name)

#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);

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
