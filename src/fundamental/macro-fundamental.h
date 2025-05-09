/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "forward-fundamental.h"

/* Temporarily disable some warnings */
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

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

#define DISABLE_WARNING_STRINGOP_OVERREAD                               \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wstringop-overread\"")

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define DISABLE_WARNING_TYPE_LIMITS                                     \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")

#define DISABLE_WARNING_STRINGOP_TRUNCATION                             \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wstringop-truncation\"")

#define DISABLE_WARNING_REDUNDANT_DECLS                                 \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wredundant-decls\"")

#if HAVE_WARNING_ZERO_LENGTH_BOUNDS
#  define DISABLE_WARNING_ZERO_LENGTH_BOUNDS                            \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wzero-length-bounds\"")
#else
#  define DISABLE_WARNING_ZERO_LENGTH_BOUNDS                            \
        _Pragma("GCC diagnostic push")
#endif

#if HAVE_WARNING_ZERO_AS_NULL_POINTER_CONSTANT
#  define DISABLE_WARNING_ZERO_AS_NULL_POINTER_CONSTANT                 \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wzero-as-null-pointer-constant\"")
#else
#  define DISABLE_WARNING_ZERO_AS_NULL_POINTER_CONSTANT                 \
        _Pragma("GCC diagnostic push")
#endif

/* C23 changed char8_t from char to unsigned char, hence we cannot pass u8 literals to e.g. fputs() without
 * casting. Let's introduce our own way to declare UTF-8 literals, which casts u8 literals to const char*. */
#define UTF8(s) ((const char*) (u8"" s))

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))

/* Note that this works differently from pthread_once(): this macro does
 * not synchronize code execution, i.e. code that is run conditionalized
 * on this macro will run concurrently to all other code conditionalized
 * the same way, there's no ordering or completion enforced. */
#define ONCE __ONCE(UNIQ_T(_once_, UNIQ))
#define __ONCE(o)                                                  \
        ({                                                         \
                static bool (o) = false;                           \
                __atomic_exchange_n(&(o), true, __ATOMIC_SEQ_CST); \
        })

#define U64_KB UINT64_C(1024)
#define U64_MB (UINT64_C(1024) * U64_KB)
#define U64_GB (UINT64_C(1024) * U64_MB)

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

#define MIN3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MIN(x, y);         \
                MIN(_c, z);                             \
        })

/* Returns true if the passed integer is a positive power of two */
#define CONST_ISPOWEROF2(x)                     \
        ((x) > 0 && ((x) & ((x) - 1)) == 0)

#define ISPOWEROF2(x)                                                  \
        __builtin_choose_expr(                                         \
                __builtin_constant_p(x),                               \
                CONST_ISPOWEROF2(x),                                   \
                ({                                                     \
                        const typeof(x) _x = (x);                      \
                        CONST_ISPOWEROF2(_x);                          \
                }))

#define ADD_SAFE(ret, a, b) (!__builtin_add_overflow(a, b, ret))
#define INC_SAFE(a, b) __INC_SAFE(UNIQ, a, b)
#define __INC_SAFE(q, a, b)                                     \
        ({                                                      \
                const typeof(a) UNIQ_T(A, q) = (a);             \
                ADD_SAFE(UNIQ_T(A, q), *UNIQ_T(A, q), b);       \
        })

#define SUB_SAFE(ret, a, b) (!__builtin_sub_overflow(a, b, ret))
#define DEC_SAFE(a, b) __DEC_SAFE(UNIQ, a, b)
#define __DEC_SAFE(q, a, b)                                     \
        ({                                                      \
                const typeof(a) UNIQ_T(A, q) = (a);             \
                SUB_SAFE(UNIQ_T(A, q), *UNIQ_T(A, q), b);       \
        })

#define MUL_SAFE(ret, a, b) (!__builtin_mul_overflow(a, b, ret))
#define MUL_ASSIGN_SAFE(a, b) __MUL_ASSIGN_SAFE(UNIQ, a, b)
#define __MUL_ASSIGN_SAFE(q, a, b)                              \
        ({                                                      \
                const typeof(a) UNIQ_T(A, q) = (a);             \
                MUL_SAFE(UNIQ_T(A, q), *UNIQ_T(A, q), b);       \
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

/* Rounds up x to the next multiple of y. Resolves to typeof(x) -1 in case of overflow */
#define __ROUND_UP(q, x, y)                                             \
        ({                                                              \
                const typeof(y) UNIQ_T(A, q) = (y);                     \
                const typeof(x) UNIQ_T(B, q) = DIV_ROUND_UP((x), UNIQ_T(A, q)); \
                typeof(x) UNIQ_T(C, q);                                 \
                MUL_SAFE(&UNIQ_T(C, q), UNIQ_T(B, q), UNIQ_T(A, q)) ? UNIQ_T(C, q) : (typeof(x)) -1; \
        })
#define ROUND_UP(x, y) __ROUND_UP(UNIQ, (x), (y))

#define  CASE_F_1(X)      case X:
#define  CASE_F_2(X, ...) case X:  CASE_F_1( __VA_ARGS__)
#define  CASE_F_3(X, ...) case X:  CASE_F_2( __VA_ARGS__)
#define  CASE_F_4(X, ...) case X:  CASE_F_3( __VA_ARGS__)
#define  CASE_F_5(X, ...) case X:  CASE_F_4( __VA_ARGS__)
#define  CASE_F_6(X, ...) case X:  CASE_F_5( __VA_ARGS__)
#define  CASE_F_7(X, ...) case X:  CASE_F_6( __VA_ARGS__)
#define  CASE_F_8(X, ...) case X:  CASE_F_7( __VA_ARGS__)
#define  CASE_F_9(X, ...) case X:  CASE_F_8( __VA_ARGS__)
#define CASE_F_10(X, ...) case X:  CASE_F_9( __VA_ARGS__)
#define CASE_F_11(X, ...) case X: CASE_F_10( __VA_ARGS__)
#define CASE_F_12(X, ...) case X: CASE_F_11( __VA_ARGS__)
#define CASE_F_13(X, ...) case X: CASE_F_12( __VA_ARGS__)
#define CASE_F_14(X, ...) case X: CASE_F_13( __VA_ARGS__)
#define CASE_F_15(X, ...) case X: CASE_F_14( __VA_ARGS__)
#define CASE_F_16(X, ...) case X: CASE_F_15( __VA_ARGS__)
#define CASE_F_17(X, ...) case X: CASE_F_16( __VA_ARGS__)
#define CASE_F_18(X, ...) case X: CASE_F_17( __VA_ARGS__)
#define CASE_F_19(X, ...) case X: CASE_F_18( __VA_ARGS__)
#define CASE_F_20(X, ...) case X: CASE_F_19( __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (__VA_ARGS__)

#define IN_SET(x, first, ...)                                           \
        ({                                                              \
                bool _found = false;                                    \
                /* If the build breaks in the line below, you need to extend the case macros. We use typeof(+x) \
                 * here to widen the type of x if it is a bit-field as this would otherwise be illegal. */      \
                static const typeof(+x) __assert_in_set[] _unused_ = { first, __VA_ARGS__ }; \
                assert_cc(ELEMENTSOF(__assert_in_set) <= 20);           \
                switch (x) {                                            \
                FOR_EACH_MAKE_CASE(first, __VA_ARGS__)                  \
                        _found = true;                                  \
                        break;                                          \
                default:                                                \
                        ;                                               \
                }                                                       \
                _found;                                                 \
        })

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_GENERIC(var, type, nullvalue)                       \
        ({                                                       \
                type *_pvar_ = &(var);                           \
                type _var_ = *_pvar_;                            \
                type _nullvalue_ = nullvalue;                    \
                *_pvar_ = _nullvalue_;                           \
                _var_;                                           \
        })
#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_STRUCT_TYPE(s, type) TAKE_GENERIC(s, type, {})
#define TAKE_STRUCT(s) TAKE_STRUCT_TYPE(s, typeof(s))

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

/* Declares an ELF read-only string section that does not occupy memory at runtime. */
#define DECLARE_NOALLOC_SECTION(name, text)   \
        asm(".pushsection " name ",\"S\"\n\t" \
            ".ascii " STRINGIFY(text) "\n\t"  \
            ".popsection\n")

#ifdef SBAT_DISTRO
        #define DECLARE_SBAT(text) DECLARE_NOALLOC_SECTION(".sbat", text)
#else
        #define DECLARE_SBAT(text)
#endif

#define sizeof_field(struct_type, member) sizeof(((struct_type *) 0)->member)
#define endoffsetof_field(struct_type, member) (offsetof(struct_type, member) + sizeof_field(struct_type, member))
#define voffsetof(v, member) offsetof(typeof(v), member)

#define _FOREACH_ARRAY(i, array, num, m, end)                           \
        for (typeof(array[0]) *i = (array), *end = ({                   \
                                typeof(num) m = (num);                  \
                                (i && m > 0) ? i + m : NULL;            \
                        }); end && i < end; i++)

#define FOREACH_ARRAY(i, array, num)                                    \
        _FOREACH_ARRAY(i, array, num, UNIQ_T(m, UNIQ), UNIQ_T(end, UNIQ))

#define FOREACH_ELEMENT(i, array)                                 \
        FOREACH_ARRAY(i, array, ELEMENTSOF(array))

#define PTR_TO_SIZE(p) ((size_t) ((uintptr_t) (p)))
#define SIZE_TO_PTR(u) ((void *) ((uintptr_t) (u)))
