/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef SD_BOOT
#include <assert.h>
#endif

#include "type.h"

#define _const_ __attribute__((__const__))
#define _pure_ __attribute__((__pure__))
#define _unused_ __attribute__((__unused__))
#define _cleanup_(x) __attribute__((__cleanup__(x)))

#ifndef __COVERITY__
#  define VOID_0 ((void)0)
#else
#  define VOID_0 ((void*)0)
#endif

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

#ifdef SD_BOOT
#define assert(expr) do {} while (false)
#endif

#if defined(static_assert)
#define assert_cc(expr)                                                 \
        static_assert(expr, #expr)
#else
#define assert_cc(expr)                                                 \
        struct CONCATENATE(_assert_struct_, __COUNTER__) {              \
                char x[(expr) ? 0 : -1];                                \
        }
#endif

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

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MAX(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                VOID_0))

/* takes two types and returns the size of the larger one */
#define MAXSIZE(A, B) (sizeof(union _packed_ { typeof(A) a; typeof(B) b; }))

#define MAX3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MAX(x, y);         \
                MAX(_c, z);                             \
        })

#define MAX4(x, y, z, a)                                \
        ({                                              \
                const typeof(x) _d = MAX3(x, y, z);     \
                MAX(_d, a);                             \
        })

#undef MIN
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define __MIN(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

/* evaluates to (void) if _A or _B are not constant or of different types */
#define CONST_MIN(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) < (_B)) ? (_A) : (_B),                            \
                VOID_0))

#define MIN3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MIN(x, y);         \
                MIN(_c, z);                             \
        })

#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define __LESS_BY(aq, a, bq, b)                         \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) - UNIQ_T(B, bq) : 0; \
        })

#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define __CMP(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? -1 :    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? 1 : 0;  \
        })

#undef CLAMP
#define CLAMP(x, low, high) __CLAMP(UNIQ, (x), UNIQ, (low), UNIQ, (high))
#define __CLAMP(xq, x, lowq, low, highq, high)                          \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(low) UNIQ_T(LOW, lowq) = (low);            \
                const typeof(high) UNIQ_T(HIGH, highq) = (high);        \
                        UNIQ_T(X, xq) > UNIQ_T(HIGH, highq) ?           \
                                UNIQ_T(HIGH, highq) :                   \
                                UNIQ_T(X, xq) < UNIQ_T(LOW, lowq) ?     \
                                        UNIQ_T(LOW, lowq) :             \
                                        UNIQ_T(X, xq);                  \
        })

/* [(x + y - 1) / y] suffers from an integer overflow, even though the
 * computation should be possible in the given type. Therefore, we use
 * [x / y + !!(x % y)]. Note that on "Real CPUs" a division returns both the
 * quotient and the remainder, so both should be equally fast. */
#define DIV_ROUND_UP(x, y) __DIV_ROUND_UP(UNIQ, (x), UNIQ, (y))
#define __DIV_ROUND_UP(xq, x, yq, y)                                    \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(y) UNIQ_T(Y, yq) = (y);                    \
                (UNIQ_T(X, xq) / UNIQ_T(Y, yq) + !!(UNIQ_T(X, xq) % UNIQ_T(Y, yq))); \
        })

#define CASE_F(X) case X:
#define CASE_F_1(CASE, X) CASE_F(X)
#define CASE_F_2(CASE, X, ...)  CASE(X) CASE_F_1(CASE, __VA_ARGS__)
#define CASE_F_3(CASE, X, ...)  CASE(X) CASE_F_2(CASE, __VA_ARGS__)
#define CASE_F_4(CASE, X, ...)  CASE(X) CASE_F_3(CASE, __VA_ARGS__)
#define CASE_F_5(CASE, X, ...)  CASE(X) CASE_F_4(CASE, __VA_ARGS__)
#define CASE_F_6(CASE, X, ...)  CASE(X) CASE_F_5(CASE, __VA_ARGS__)
#define CASE_F_7(CASE, X, ...)  CASE(X) CASE_F_6(CASE, __VA_ARGS__)
#define CASE_F_8(CASE, X, ...)  CASE(X) CASE_F_7(CASE, __VA_ARGS__)
#define CASE_F_9(CASE, X, ...)  CASE(X) CASE_F_8(CASE, __VA_ARGS__)
#define CASE_F_10(CASE, X, ...) CASE(X) CASE_F_9(CASE, __VA_ARGS__)
#define CASE_F_11(CASE, X, ...) CASE(X) CASE_F_10(CASE, __VA_ARGS__)
#define CASE_F_12(CASE, X, ...) CASE(X) CASE_F_11(CASE, __VA_ARGS__)
#define CASE_F_13(CASE, X, ...) CASE(X) CASE_F_12(CASE, __VA_ARGS__)
#define CASE_F_14(CASE, X, ...) CASE(X) CASE_F_13(CASE, __VA_ARGS__)
#define CASE_F_15(CASE, X, ...) CASE(X) CASE_F_14(CASE, __VA_ARGS__)
#define CASE_F_16(CASE, X, ...) CASE(X) CASE_F_15(CASE, __VA_ARGS__)
#define CASE_F_17(CASE, X, ...) CASE(X) CASE_F_16(CASE, __VA_ARGS__)
#define CASE_F_18(CASE, X, ...) CASE(X) CASE_F_17(CASE, __VA_ARGS__)
#define CASE_F_19(CASE, X, ...) CASE(X) CASE_F_18(CASE, __VA_ARGS__)
#define CASE_F_20(CASE, X, ...) CASE(X) CASE_F_19(CASE, __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (CASE_F,__VA_ARGS__)

#define IN_SET(x, ...)                          \
        ({                                      \
                sd_bool _found = false;         \
                /* If the build breaks in the line below, you need to extend the case macros. (We use "long double" as  \
                 * type for the array, in the hope that checkers such as ubsan don't complain that the initializers for \
                 * the array are not representable by the base type. Ideally we'd use typeof(x) as base type, but that  \
                 * doesn't work, as we want to use this on bitfields and gcc refuses typeof() on bitfields.) */         \
                static const long double __assert_in_set[] _unused_ = { __VA_ARGS__ }; \
                assert_cc(ELEMENTSOF(__assert_in_set) <= 20); \
                switch(x) {                     \
                FOR_EACH_MAKE_CASE(__VA_ARGS__) \
                        _found = true;          \
                        break;                  \
                default:                        \
                        break;                  \
                }                               \
                _found;                         \
        })

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_PTR(ptr)                           \
        ({                                      \
                typeof(ptr) _ptr_ = (ptr);      \
                (ptr) = NULL;                   \
                _ptr_;                          \
        })
