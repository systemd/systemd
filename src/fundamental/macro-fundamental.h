/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !SD_BOOT
#  include <assert.h>
#endif

#include <limits.h>
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

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define DISABLE_WARNING_TYPE_LIMITS                                     \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")

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

#if __GNUC__ >= 7 || (defined(__clang__) && __clang_major__ >= 10)
#  define _fallthrough_ __attribute__((__fallthrough__))
#else
#  define _fallthrough_
#endif

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

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

#if SD_BOOT
        _noreturn_ void efi_assert(const char *expr, const char *file, unsigned line, const char *function);

        #ifdef NDEBUG
                #define assert(expr) ({ if (!(expr)) __builtin_unreachable(); })
                #define assert_not_reached() __builtin_unreachable()
        #else
                #define assert(expr) ({ _likely_(expr) ? VOID_0 : efi_assert(#expr, __FILE__, __LINE__, __func__); })
                #define assert_not_reached() efi_assert("Code should not be reached", __FILE__, __LINE__, __func__)
        #endif
        #define static_assert _Static_assert
        #define assert_se(expr) ({ _likely_(expr) ? VOID_0 : efi_assert(#expr, __FILE__, __LINE__, __func__); })
#endif

/* This passes the argument through after (if asserts are enabled) checking that it is not null. */
#define ASSERT_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert)
#define ASSERT_SE_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert_se)
#define _ASSERT_PTR(expr, var, check)      \
        ({                                 \
                typeof(expr) var = (expr); \
                check(var);                \
                var;                       \
        })

#define ASSERT_NONNEG(expr)                              \
        ({                                               \
                typeof(expr) _expr_ = (expr), _zero = 0; \
                assert(_expr_ >= _zero);                 \
                _expr_;                                  \
        })

#define ASSERT_SE_NONNEG(expr)                           \
        ({                                               \
                typeof(expr) _expr_ = (expr), _zero = 0; \
                assert_se(_expr_ >= _zero);              \
                _expr_;                                  \
        })

#define assert_cc(expr) static_assert(expr, #expr)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

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

#undef MAX
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define __MAX(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })

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
                __builtin_mul_overflow(UNIQ_T(B, q), UNIQ_T(A, q), &UNIQ_T(C, q)) ? (typeof(x)) -1 : UNIQ_T(C, q); \
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
                        break;                                          \
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

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

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

#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)

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

/* Declares an ELF read-only string section that does not occupy memory at runtime. */
#define DECLARE_NOALLOC_SECTION(name, text)   \
        asm(".pushsection " name ",\"S\"\n\t" \
            ".ascii " STRINGIFY(text) "\n\t"  \
            ".zero 1\n\t"                     \
            ".popsection\n")

#ifdef SBAT_DISTRO
        #define DECLARE_SBAT(text) DECLARE_NOALLOC_SECTION(".sbat", text)
#else
        #define DECLARE_SBAT(text)
#endif
