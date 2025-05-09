/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DISABLE_WARNING_ADDRESS                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Waddress\"")

#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")

#define _align_(x) __attribute__((__aligned__(x)))
#define _alignas_(x) __attribute__((__aligned__(alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void *))))
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _const_ __attribute__((__const__))
#define _deprecated_ __attribute__((__deprecated__))
#define _destructor_ __attribute__((__destructor__))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _malloc_ __attribute__((__malloc__))
#define _noinline_ __attribute__((noinline))
#define _noreturn_ _Noreturn
#define _packed_ __attribute__((__packed__))
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _public_ __attribute__((__visibility__("default")))
#define _pure_ __attribute__((__pure__))
#define _retain_ __attribute__((__retain__))
#define _returns_nonnull_ __attribute__((__returns_nonnull__))
#define _section_(x) __attribute__((__section__(x)))
#define _sentinel_ __attribute__((__sentinel__))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _unused_ __attribute__((__unused__))
#define _used_ __attribute__((__used__))
#define _warn_unused_result_ __attribute__((__warn_unused_result__))
#define _weak_ __attribute__((__weak__))
#define _weakref_(x) __attribute__((__weakref__(#x)))

#ifdef __clang__
#  define _alloc_(...)
#else
#  define _alloc_(...) __attribute__((__alloc_size__(__VA_ARGS__)))
#endif

#if defined(__clang__) && __clang_major__ < 10
#  define _fallthrough_
#else
#  define _fallthrough_ __attribute__((__fallthrough__))
#endif

#if __GNUC__ >= 15
#  define _nonnull_if_nonzero_(p, n) __attribute__((nonnull_if_nonzero(p, n)))
#else
#  define _nonnull_if_nonzero_(p, n)
#endif

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define assert_cc(expr) _Static_assert(expr, #expr)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

#ifdef __clang__
#  define ABS(a) __builtin_llabs(a)
#else
#  define ABS(a) __builtin_imaxabs(a)
#endif
assert_cc(sizeof(intmax_t) <= sizeof(long long));

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof(""x"") - sizeof(typeof(x[0])))

typedef struct {
        int _empty[0];
} dummy_t;

assert_cc(sizeof(dummy_t) == 0);

/* Restriction/bug (see below) was fixed in GCC 15 and clang 19. */
#if __GNUC__ >= 15 || (defined(__clang__) && __clang_major__ >= 19)
#define DECLARE_FLEX_ARRAY(type, name) type name[]
#else
/* Declare a flexible array usable in a union.
 * This is essentially a work-around for a pointless constraint in C99
 * and might go away in some future version of the standard.
 *
 * See https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3080ea5553cc909b000d1f1d964a9041962f2c5b
 */
#define DECLARE_FLEX_ARRAY(type, name)                 \
        struct {                                       \
                dummy_t __empty__ ## name;             \
                type name[];                           \
        }
#endif

assert_cc(STRLEN(__FILE__) > STRLEN(RELATIVE_SOURCE_PATH) + 1);
#define PROJECT_FILE (&__FILE__[STRLEN(RELATIVE_SOURCE_PATH) + 1])

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

#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)


#ifndef __COVERITY__
#  define VOID_0 ((void)0)
#else
#  define VOID_0 ((void*)0)
#endif

#define IS_UNSIGNED_INTEGER_TYPE(type) \
        (__builtin_types_compatible_p(typeof(type), unsigned char) ||   \
         __builtin_types_compatible_p(typeof(type), unsigned short) ||  \
         __builtin_types_compatible_p(typeof(type), unsigned) ||        \
         __builtin_types_compatible_p(typeof(type), unsigned long) ||   \
         __builtin_types_compatible_p(typeof(type), unsigned long long))

#define IS_SIGNED_INTEGER_TYPE(type) \
        (__builtin_types_compatible_p(typeof(type), signed char) ||   \
         __builtin_types_compatible_p(typeof(type), signed short) ||  \
         __builtin_types_compatible_p(typeof(type), signed) ||        \
         __builtin_types_compatible_p(typeof(type), signed long) ||   \
         __builtin_types_compatible_p(typeof(type), signed long long))

/* Evaluates to (void) if _A or _B are not constant or of different types (being integers of different sizes
 * is also OK as long as the signedness matches) */
#define CONST_MAX(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                (__builtin_types_compatible_p(typeof(_A), typeof(_B)) || \
                 (IS_UNSIGNED_INTEGER_TYPE(_A) && IS_UNSIGNED_INTEGER_TYPE(_B)) || \
                 (IS_SIGNED_INTEGER_TYPE(_A) && IS_SIGNED_INTEGER_TYPE(_B))), \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                VOID_0))

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MIN(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) < (_B)) ? (_A) : (_B),                            \
                VOID_0))
