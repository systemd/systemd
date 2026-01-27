/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#define DISABLE_WARNING_ADDRESS                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Waddress\"")

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

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

/* C23 changed char8_t from char to unsigned char, hence we cannot pass u8 literals to e.g. fputs() without
 * casting. Let's introduce our own way to declare UTF-8 literals, which casts u8 literals to const char*. */
#define UTF8(s) ((const char*) (u8"" s))

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

#define assert_cc(expr) _Static_assert(expr, #expr)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

/* The macro is true when the code block is called first time, and is false for the second and later times.
 * Note that this works differently from pthread_once(): this macro does not synchronize code execution, i.e.
 * code that is run conditionalized on this macro will run concurrently to all other code conditionalized the
 * same way, there's no ordering or completion enforced. */
#define ONCE __ONCE(UNIQ_T(_once_, UNIQ))
#define __ONCE(o)                                                       \
        ({                                                              \
                static bool (o) = false;                                \
                !__atomic_exchange_n(&(o), true, __ATOMIC_SEQ_CST);     \
        })

#define U64_KB UINT64_C(1024)
#define U64_MB (UINT64_C(1024) * U64_KB)
#define U64_GB (UINT64_C(1024) * U64_MB)

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

#ifdef __clang__
#  define ABS(a) __builtin_llabs(a)
#else
#  define ABS(a) __builtin_imaxabs(a)
#endif
assert_cc(sizeof(long long) == sizeof(intmax_t));

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
#define CASE_F_21(X, ...) case X: CASE_F_20( __VA_ARGS__)
#define CASE_F_22(X, ...) case X: CASE_F_21( __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_22,CASE_F_21,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12, \
                               CASE_F_11,CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (__VA_ARGS__)

#define IN_SET(x, first, ...)                                           \
        ({                                                              \
                bool _found = false;                                    \
                /* If the build breaks in the line below, you need to extend the case macros. We use typeof(+x) \
                 * here to widen the type of x if it is a bit-field as this would otherwise be illegal. */      \
                static const typeof(+x) __assert_in_set[] _unused_ = { first, __VA_ARGS__ }; \
                assert_cc(ELEMENTSOF(__assert_in_set) <= 22);           \
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

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof(""x"") - sizeof(typeof(x[0])))

DISABLE_WARNING_REDUNDANT_DECLS;
void free(void *p); /* NOLINT (readability-redundant-declaration) */
REENABLE_WARNING;

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)

typedef struct {
        int _empty[0];
} dummy_t;

assert_cc(sizeof(dummy_t) == 0);

/* Restriction/bug (see below) was fixed in GCC 15 and clang 19. */
#if __GNUC__ >= 15 || (defined(__clang__) && __clang_major__ >= 19)
#  define DECLARE_FLEX_ARRAY(type, name) type name[]
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

/* Declare an ELF read-only string section that does not occupy memory at runtime. */
#define DECLARE_NOALLOC_SECTION(name, text)           \
        asm(".pushsection " name ",\"S\"\n\t"         \
            ".ascii " STRINGIFY(text) "\n\t"          \
            ".popsection\n")

/* Similar to DECLARE_NOALLOC_SECTION, but pad the section with extra 512 bytes. After taking alignment into
 * account, the section has up to 1024 bytes minus the size of the original content of padding, and this
 * extra space can be used to extend the contents. This is intended for the .sbat section. */
#define DECLARE_NOALLOC_SECTION_PADDED(name, text)    \
        assert_cc(STRLEN(text) <= 512);               \
        asm(".pushsection " name ",\"S\"\n\t"         \
            ".ascii " STRINGIFY(text) "\n\t"          \
            ".balign 512\n\t"                         \
            ".fill 512, 1, 0\n\t"                     \
            ".popsection\n")

#define typeof_field(struct_type, member) typeof(((struct_type *) 0)->member)
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

assert_cc(STRLEN(__FILE__) > STRLEN(RELATIVE_SOURCE_PATH) + 1);
#define PROJECT_FILE (&__FILE__[STRLEN(RELATIVE_SOURCE_PATH) + 1])

/* In GCC 14 (C23) we can force enums to have the right types, and not solely rely on language extensions anymore */
#if (__GNUC__ >= 14 || __STDC_VERSION__ >= 202311L) && !defined(__EDG__)
#  define ENUM_TYPE_S64(id) id : int64_t
#else
#  define ENUM_TYPE_S64(id) id
#endif

/* This macro is used to have a const-returning and non-const returning version of a function based on
 * whether its first argument is const or not (e.g. strstr()). */
#define const_generic(ptr, call)                              \
        _Generic(0 ? (ptr) : (void*) 1,                       \
                 const void*: (const typeof(*call)*) (call),  \
                 void*: (call))
