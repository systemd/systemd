/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* A type-safe atomic refcounter.
 *
 * DO NOT USE THIS UNLESS YOU ACTUALLY CARE ABOUT THREAD SAFETY! */

typedef struct {
        volatile unsigned _value;
} RefCount;

#define REFCNT_GET(r) ((r)._value)
#define REFCNT_INC(r) (__sync_add_and_fetch(&(r)._value, 1))
#define REFCNT_DEC(r) (__sync_sub_and_fetch(&(r)._value, 1))

#define REFCNT_INIT ((RefCount) { ._value = 1 })

#define _DEFINE_ATOMIC_REF_FUNC(type, name, scope)                    \
        scope type *name##_ref(type *p) {                               \
                if (!p)                                                 \
                        return NULL;                                    \
                                                                        \
                assert_se(REFCNT_INC(p->n_ref) >= 2);                   \
                return p;                                               \
        }

#define _DEFINE_ATOMIC_UNREF_FUNC(type, name, free_func, scope)       \
        scope type *name##_unref(type *p) {                             \
                if (!p)                                                 \
                        return NULL;                                    \
                                                                        \
                if (REFCNT_DEC(p->n_ref) > 0)                           \
                        return NULL;                                    \
                                                                        \
                return free_func(p);                                    \
        }

#define DEFINE_ATOMIC_REF_FUNC(type, name)    \
        _DEFINE_ATOMIC_REF_FUNC(type, name,)
#define DEFINE_PUBLIC_ATOMIC_REF_FUNC(type, name)     \
        _DEFINE_ATOMIC_REF_FUNC(type, name, _public_)

#define DEFINE_ATOMIC_UNREF_FUNC(type, name, free_func)       \
        _DEFINE_ATOMIC_UNREF_FUNC(type, name, free_func,)
#define DEFINE_PUBLIC_ATOMIC_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_ATOMIC_UNREF_FUNC(type, name, free_func, _public_)

#define DEFINE_ATOMIC_REF_UNREF_FUNC(type, name, free_func)   \
        DEFINE_ATOMIC_REF_FUNC(type, name);                   \
        DEFINE_ATOMIC_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_ATOMIC_REF_UNREF_FUNC(type, name, free_func)   \
        DEFINE_PUBLIC_ATOMIC_REF_FUNC(type, name);                   \
        DEFINE_PUBLIC_ATOMIC_UNREF_FUNC(type, name, free_func);
