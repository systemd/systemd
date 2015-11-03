/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/types.h>

#define _printf_(a,b) __attribute__ ((format (printf, a, b)))
#define _alloc_(...) __attribute__ ((alloc_size(__VA_ARGS__)))
#define _sentinel_ __attribute__ ((sentinel))
#define _unused_ __attribute__ ((unused))
#define _destructor_ __attribute__ ((destructor))
#define _pure_ __attribute__ ((pure))
#define _const_ __attribute__ ((const))
#define _deprecated_ __attribute__ ((deprecated))
#define _packed_ __attribute__ ((packed))
#define _malloc_ __attribute__ ((malloc))
#define _weak_ __attribute__ ((weak))
#define _likely_(x) (__builtin_expect(!!(x),1))
#define _unlikely_(x) (__builtin_expect(!!(x),0))
#define _public_ __attribute__ ((visibility("default")))
#define _hidden_ __attribute__ ((visibility("hidden")))
#define _weakref_(x) __attribute__((weakref(#x)))
#define _alignas_(x) __attribute__((aligned(__alignof(x))))
#define _cleanup_(x) __attribute__((cleanup(x)))

/* Temporarily disable some warnings */
#define DISABLE_WARNING_DECLARATION_AFTER_STATEMENT                     \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")

#define DISABLE_WARNING_FORMAT_NONLITERAL                               \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")

#define DISABLE_WARNING_MISSING_PROTOTYPES                              \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")

#define DISABLE_WARNING_NONNULL                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wnonnull\"")

#define DISABLE_WARNING_SHADOW                                          \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\"")

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")

/* automake test harness */
#define EXIT_TEST_SKIP 77

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

/* Rounds up */

#define ALIGN4(l) (((l) + 3) & ~3)
#define ALIGN8(l) (((l) + 7) & ~7)

#if __SIZEOF_POINTER__ == 8
#define ALIGN(l) ALIGN8(l)
#elif __SIZEOF_POINTER__ == 4
#define ALIGN(l) ALIGN4(l)
#else
#error "Wut? Pointers are neither 4 nor 8 bytes long?"
#endif

#define ALIGN_PTR(p) ((void*) ALIGN((unsigned long) (p)))
#define ALIGN4_PTR(p) ((void*) ALIGN4((unsigned long) (p)))
#define ALIGN8_PTR(p) ((void*) ALIGN8((unsigned long) (p)))

static inline size_t ALIGN_TO(size_t l, size_t ali) {
        return ((l + ali - 1) & ~(ali - 1));
}

#define ALIGN_TO_PTR(p, ali) ((void*) ALIGN_TO((unsigned long) (p), (ali)))

/* align to next higher power-of-2 (except for: 0 => 0, overflow => 0) */
static inline unsigned long ALIGN_POWER2(unsigned long u) {
        /* clz(0) is undefined */
        if (u == 1)
                return 1;

        /* left-shift overflow is undefined */
        if (__builtin_clzl(u - 1UL) < 1)
                return 0;

        return 1UL << (sizeof(u) * 8 - __builtin_clzl(u - 1UL));
}

#define ELEMENTSOF(x)                                                    \
        __extension__ (__builtin_choose_expr(                            \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                                \
                (void)0))
/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define container_of(ptr, type, member) __container_of(UNIQ, (ptr), type, member)
#define __container_of(uniq, ptr, type, member)                         \
        __extension__ ({                                                \
                const typeof( ((type*)0)->member ) *UNIQ_T(A, uniq) = (ptr); \
                (type*)( (char *)UNIQ_T(A, uniq) - offsetof(type,member) ); \
        })

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        __extension__ ({                                \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A,aq) > UNIQ_T(B,bq) ? UNIQ_T(A,aq) : UNIQ_T(B,bq); \
        })

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MAX(_A, _B) \
        __extension__ (__builtin_choose_expr(                           \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                (void)0))

/* takes two types and returns the size of the larger one */
#define MAXSIZE(A, B) (sizeof(union _packed_ { typeof(A) a; typeof(B) b; }))

#define MAX3(x,y,z)                                     \
        __extension__ ({                                \
                        const typeof(x) _c = MAX(x,y);  \
                        MAX(_c, z);                     \
                })

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        __extension__ ({                                \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A,aq) < UNIQ_T(B,bq) ? UNIQ_T(A,aq) : UNIQ_T(B,bq); \
        })

#define MIN3(x,y,z)                                     \
        __extension__ ({                                \
                        const typeof(x) _c = MIN(x,y);  \
                        MIN(_c, z);                     \
                })

#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define __LESS_BY(aq, a, bq, b)                         \
        __extension__ ({                                \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A,aq) > UNIQ_T(B,bq) ? UNIQ_T(A,aq) - UNIQ_T(B,bq) : 0; \
        })

#undef CLAMP
#define CLAMP(x, low, high) __CLAMP(UNIQ, (x), UNIQ, (low), UNIQ, (high))
#define __CLAMP(xq, x, lowq, low, highq, high)                          \
        __extension__ ({                                                \
                const typeof(x) UNIQ_T(X,xq) = (x);                     \
                const typeof(low) UNIQ_T(LOW,lowq) = (low);             \
                const typeof(high) UNIQ_T(HIGH,highq) = (high);         \
                        UNIQ_T(X,xq) > UNIQ_T(HIGH,highq) ?             \
                                UNIQ_T(HIGH,highq) :                    \
                                UNIQ_T(X,xq) < UNIQ_T(LOW,lowq) ?       \
                                        UNIQ_T(LOW,lowq) :              \
                                        UNIQ_T(X,xq);                   \
        })

/* [(x + y - 1) / y] suffers from an integer overflow, even though the
 * computation should be possible in the given type. Therefore, we use
 * [x / y + !!(x % y)]. Note that on "Real CPUs" a division returns both the
 * quotient and the remainder, so both should be equally fast. */
#define DIV_ROUND_UP(_x, _y)                                            \
        __extension__ ({                                                \
                const typeof(_x) __x = (_x);                            \
                const typeof(_y) __y = (_y);                            \
                (__x / __y + !!(__x % __y));                            \
        })

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#define assert_se(expr) assert_message_se(expr, #expr)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while(false)
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

#define assert_not_reached(t)                                           \
        do {                                                            \
                log_assert_failed_unreachable(t, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#if defined(static_assert)
/* static_assert() is sometimes defined in a way that trips up
 * -Wdeclaration-after-statement, hence let's temporarily turn off
 * this warning around it. */
#define assert_cc(expr)                                                 \
        DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                    \
        static_assert(expr, #expr);                                     \
        REENABLE_WARNING
#else
#define assert_cc(expr)                                                 \
        DISABLE_WARNING_DECLARATION_AFTER_STATEMENT;                    \
        struct CONCATENATE(_assert_struct_, __COUNTER__) {              \
                char x[(expr) ? 0 : -1];                                \
        };                                                              \
        REENABLE_WARNING
#endif

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, __FILE__, __LINE__, __PRETTY_FUNCTION__), false))

#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr, #expr))                           \
                        return (r);                                     \
        } while (false)

#define assert_return_errno(expr, r, err)                               \
        do {                                                            \
                if (!assert_log(expr, #expr)) {                         \
                        errno = err;                                    \
                        return (r);                                     \
                }                                                       \
        } while (false)

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define LONG_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define ULONG_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define INT32_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define UINT32_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_INT64(p) ((int64_t) ((intptr_t) (p)))
#define INT64_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT64(p) ((uint64_t) ((uintptr_t) (p)))
#define UINT64_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_SIZE(p) ((size_t) ((uintptr_t) (p)))
#define SIZE_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define CHAR_TO_STR(x) ((char[2]) { x, 0 })

#define char_array_0(x) x[sizeof(x)-1] = 0;

/* Returns the number of chars needed to format variables of the
 * specified type as a decimal string. Adds in extra space for a
 * negative '-' prefix (hence works correctly on signed
 * types). Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                           \
        (2+(sizeof(type) <= 1 ? 3 :                                     \
            sizeof(type) <= 2 ? 5 :                                     \
            sizeof(type) <= 4 ? 10 :                                    \
            sizeof(type) <= 8 ? 20 : sizeof(int[-2*(sizeof(type) > 8)])))

#define DECIMAL_STR_WIDTH(x)                            \
        ({                                              \
                typeof(x) _x_ = (x);                    \
                unsigned ans = 1;                       \
                while (_x_ /= 10)                       \
                        ans++;                          \
                ans;                                    \
        })

#define SET_FLAG(v, flag, b) \
        (v) = (b) ? ((v) | (flag)) : ((v) & ~(flag))

#define IN_SET(x, y, ...)                                               \
        ({                                                              \
                static const typeof(y) _array[] = { (y), __VA_ARGS__ }; \
                const typeof(y) _x = (x);                               \
                unsigned _i;                                            \
                bool _found = false;                                    \
                for (_i = 0; _i < ELEMENTSOF(_array); _i++)             \
                        if (_array[_i] == _x) {                         \
                                _found = true;                          \
                                break;                                  \
                        }                                               \
                _found;                                                 \
        })

/* Define C11 thread_local attribute even on older gcc compiler
 * version */
#ifndef thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#if __STDC_VERSION__ >= 201112L && !(defined(__STDC_NO_THREADS__) || (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#define thread_local _Thread_local
#else
#define thread_local __thread
#endif
#endif

/* Define C11 noreturn without <stdnoreturn.h> and even on older gcc
 * compiler versions */
#ifndef noreturn
#if __STDC_VERSION__ >= 201112L
#define noreturn _Noreturn
#else
#define noreturn __attribute__((noreturn))
#endif
#endif

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \
        struct __useless_struct_to_allow_trailing_semicolon__

#include "log.h"
