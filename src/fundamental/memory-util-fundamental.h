/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

#if SD_BOOT
#  include "efi-string.h"
#else
#  include <string.h>
#endif

#include "assert-fundamental.h"
#include "macro-fundamental.h"

#define memzero(x, l)                                           \
        ({                                                      \
                size_t _l_ = (l);                               \
                _l_ > 0 ? memset((x), 0, _l_) : (x);            \
        })

#if !SD_BOOT
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
        /* NB: This is a pointer to memory to erase in case of CLEANUP_ERASE(). Pointer to pointer to memory
         * to erase in case of CLEANUP_ERASE_PTR() */
        void *p;
        size_t size;
};

static inline void erase_var(struct VarEraser *e) {
        explicit_bzero_safe(e->p, e->size);
}

/* Mark var to be erased when leaving scope. */
#define CLEANUP_ERASE(var)                                              \
        _cleanup_(erase_var) _unused_ struct VarEraser CONCATENATE(_eraser_, UNIQ) = { \
                .p = &(var),                                            \
                .size = sizeof(var),                                    \
        }

static inline void erase_varp(struct VarEraser *e) {

        /* Very similar to erase_var(), but assumes `p` is a pointer to a pointer whose memory shall be destructed. */
        if (!e->p)
                return;

        explicit_bzero_safe(*(void**) e->p, e->size);
}

/* Mark pointer so that memory pointed to is erased when leaving scope. Note: this takes a pointer to the
 * specified pointer, instead of just a copy of it. This is to allow callers to invalidate the pointer after
 * use, if they like, disabling our automatic erasure (for example because they succeeded with whatever they
 * wanted to do and now intend to return the allocated buffer to their caller without it being erased). */
#define CLEANUP_ERASE_PTR(ptr, sz)                                      \
        _cleanup_(erase_varp) _unused_ struct VarEraser CONCATENATE(_eraser_, UNIQ) = { \
                .p = (ptr),                                             \
                .size = (sz),                                           \
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
                        }),                                             \
        }

/* A wrapper for 'func' to return void.
 * Only useful when a void-returning function is required by some API. */
#define DEFINE_TRIVIAL_DESTRUCTOR(name, type, func)             \
        static inline void name(type *p) {                      \
                func(p);                                        \
        }

/* When func() returns the void value (NULL, -1, …) of the appropriate type */
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        *p = func(*p);                          \
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

static inline size_t ALIGN_TO(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        if (l > SIZE_MAX - (ali - 1))
                return SIZE_MAX; /* indicate overflow */

        return ((l + (ali - 1)) & ~(ali - 1));
}

static inline uint64_t ALIGN_TO_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        if (l > UINT64_MAX - (ali - 1))
                return UINT64_MAX; /* indicate overflow */

        return ((l + (ali - 1)) & ~(ali - 1));
}

static inline size_t ALIGN_DOWN(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        return l & ~(ali - 1);
}

static inline uint64_t ALIGN_DOWN_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        return l & ~(ali - 1);
}

static inline size_t ALIGN_OFFSET(size_t l, size_t ali) {
        assert(ISPOWEROF2(ali));

        return l & (ali - 1);
}

static inline uint64_t ALIGN_OFFSET_U64(uint64_t l, uint64_t ali) {
        assert(ISPOWEROF2(ali));

        return l & (ali - 1);
}

#define ALIGN2(l) ALIGN_TO(l, 2)
#define ALIGN4(l) ALIGN_TO(l, 4)
#define ALIGN8(l) ALIGN_TO(l, 8)
#define ALIGN2_PTR(p) ((void*) ALIGN2((uintptr_t) p))
#define ALIGN4_PTR(p) ((void*) ALIGN4((uintptr_t) p))
#define ALIGN8_PTR(p) ((void*) ALIGN8((uintptr_t) p))
#define ALIGN(l)  ALIGN_TO(l, sizeof(void*))
#define ALIGN_PTR(p) ((void*) ALIGN((uintptr_t) (p)))

/* Checks if the specified pointer is aligned as appropriate for the specific type */
#define IS_ALIGNED16(p) (((uintptr_t) p) % alignof(uint16_t) == 0)
#define IS_ALIGNED32(p) (((uintptr_t) p) % alignof(uint32_t) == 0)
#define IS_ALIGNED64(p) (((uintptr_t) p) % alignof(uint64_t) == 0)

/* Same as ALIGN_TO but callable in constant contexts. */
#define CONST_ALIGN_TO(l, ali)                                         \
        __builtin_choose_expr(                                         \
                __builtin_constant_p(l) &&                             \
                __builtin_constant_p(ali) &&                           \
                CONST_ISPOWEROF2(ali) &&                               \
                (l <= SIZE_MAX - (ali - 1)),      /* overflow? */      \
                ((l) + (ali) - 1) & ~((ali) - 1),                      \
                VOID_0)

/* Similar to ((t *) (void *) (p)) to cast a pointer. The macro asserts that the pointer has a suitable
 * alignment for type "t". This exists for places where otherwise "-Wcast-align=strict" would issue a
 * warning or if you want to assert that the cast gives a pointer of suitable alignment. */
#define CAST_ALIGN_PTR(t, p)                                    \
        ({                                                      \
                const void *_p = (p);                           \
                assert(((uintptr_t) _p) % alignof(t) == 0); \
                (t *) _p;                                       \
        })
