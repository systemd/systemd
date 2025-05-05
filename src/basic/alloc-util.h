/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <malloc.h>
#include <stddef.h>

#include "macro.h"

#if HAS_FEATURE_MEMORY_SANITIZER
#  include <sanitizer/msan_interface.h>
#endif

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

#define new(t, n) ((t*) malloc_multiply(n, sizeof(t)))

#define new0(t, n) ((t*) calloc((n) ?: 1, sizeof(t)))

#define newdup(t, p, n) ((t*) memdup_multiply(p, n, sizeof(t)))

#define newdup_suffix0(t, p, n) ((t*) memdup_suffix0_multiply(p, n, sizeof(t)))

#define malloc0(n) (calloc(1, (n) ?: 1))

#define free_and_replace_full(a, b, free_func)  \
        ({                                      \
                typeof(a)* _a = &(a);           \
                typeof(b)* _b = &(b);           \
                free_func(*_a);                 \
                *_a = *_b;                      \
                *_b = NULL;                     \
                0;                              \
        })

#define free_and_replace(a, b)                  \
        free_and_replace_full(a, b, free)

/* This is similar to free_and_replace_full(), but NULL is not assigned to 'b', and its reference counter is
 * increased. */
#define unref_and_replace_full(a, b, ref_func, unref_func)      \
        ({                                       \
                typeof(a)* _a = &(a);            \
                typeof(b) _b = ref_func(b);      \
                unref_func(*_a);                 \
                *_a = _b;                        \
                0;                               \
        })

void* memdup(const void *p, size_t l) _alloc_(2);
void* memdup_suffix0(const void *p, size_t l); /* We can't use _alloc_() here, since we return a buffer one byte larger than the specified size */

static inline void unsetp(void *p) {
        /* A trivial "destructor" that can be used in cases where we want to
         * unset a pointer from a _cleanup_ function. */

        *(void**)p = NULL;
}

static inline void freep(void *p) {
        *(void**)p = mfree(*(void**) p);
}

#define _cleanup_free_ _cleanup_(freep)

static inline bool size_multiply_overflow(size_t size, size_t need) {
        return _unlikely_(need != 0 && size > (SIZE_MAX / need));
}

_malloc_ _alloc_(1, 2) static inline void *malloc_multiply(size_t need, size_t size) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return malloc(size * need ?: 1);
}

_alloc_(2, 3) static inline void *memdup_multiply(const void *p, size_t need, size_t size) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return memdup(p, size * need);
}

/* Note that we can't decorate this function with _alloc_() since the returned memory area is one byte larger
 * than the product of its parameters. */
static inline void *memdup_suffix0_multiply(const void *p, size_t need, size_t size) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return memdup_suffix0(p, size * need);
}

void* greedy_realloc(void **p, size_t need, size_t size);
void* greedy_realloc0(void **p, size_t need, size_t size);
void* greedy_realloc_append(void **p, size_t *n_p, const void *from, size_t n_from, size_t size);

#define GREEDY_REALLOC(array, need)                                     \
        greedy_realloc((void**) &(array), (need), sizeof((array)[0]))

#define GREEDY_REALLOC0(array, need)                                    \
        greedy_realloc0((void**) &(array), (need), sizeof((array)[0]))

#define GREEDY_REALLOC_APPEND(array, n_array, from, n_from)             \
        ({                                                              \
                const typeof(*(array)) *_from_ = (from);                \
                greedy_realloc_append((void**) &(array), &(n_array), _from_, (n_from), sizeof((array)[0])); \
        })

#if HAS_FEATURE_MEMORY_SANITIZER
#  define msan_unpoison(r, s) __msan_unpoison(r, s)
#else
#  define msan_unpoison(r, s)
#endif

/* Dummy allocator to tell the compiler that the new size of p is newsize. The implementation returns the
 * pointer as is; the only reason for its existence is as a conduit for the _alloc_ attribute.  This must not
 * be inlined (hence a non-static function with _noinline_ because LTO otherwise tries to inline it) because
 * gcc then loses the attributes on the function.
 * See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=96503 */
void *expand_to_usable(void *p, size_t newsize) _alloc_(2) _returns_nonnull_ _noinline_;

size_t malloc_sizeof_safe(void **xp);

/* This returns the number of usable bytes in a malloc()ed region as per malloc_usable_size(), which may
 * return a value larger than the size that was actually allocated. Access to that additional memory is
 * discouraged because it violates the C standard; a compiler cannot see that this as valid. To help the
 * compiler out, the MALLOC_SIZEOF_SAFE macro 'allocates' the usable size using a dummy allocator function
 * expand_to_usable. There is a possibility of malloc_usable_size() returning different values during the
 * lifetime of an object, which may cause problems, but the glibc allocator does not do that at the moment. */
#define MALLOC_SIZEOF_SAFE(x) \
        malloc_sizeof_safe((void**) &__builtin_choose_expr(__builtin_constant_p(x), (void*) { NULL }, (x)))

/* Inspired by ELEMENTSOF() but operates on malloc()'ed memory areas: typesafely returns the number of items
 * that fit into the specified memory block */
#define MALLOC_ELEMENTSOF(x) \
        (__builtin_choose_expr(                                         \
                __builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                MALLOC_SIZEOF_SAFE(x)/sizeof((x)[0]),                   \
                VOID_0))

/* Free every element of the array. */
void free_many(void **p, size_t n);

/* Typesafe wrapper for char** rather than void**. Unfortunately C won't implicitly cast this. */
static inline void free_many_charp(char **c, size_t n) {
        free_many((void**) c, n);
}

_alloc_(2) void *realloc0(void *p, size_t new_size);
