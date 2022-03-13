/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "macro-fundamental.h"

#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#ifdef __clang__
#  define _alloc_(...)
#else
#  define _alloc_(...) __attribute__((__alloc_size__(__VA_ARGS__)))
#endif
#define _sentinel_ __attribute__((__sentinel__))
#define _destructor_ __attribute__((__destructor__))
#define _deprecated_ __attribute__((__deprecated__))
#define _packed_ __attribute__((__packed__))
#define _malloc_ __attribute__((__malloc__))
#define _weak_ __attribute__((__weak__))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _public_ __attribute__((__visibility__("default")))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _weakref_(x) __attribute__((__weakref__(#x)))
#define _alignas_(x) __attribute__((__aligned__(__alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void*))))
#if __GNUC__ >= 7
#define _fallthrough_ __attribute__((__fallthrough__))
#else
#define _fallthrough_
#endif
/* Define C11 noreturn without <stdnoreturn.h> and even on older gcc
 * compiler versions */
#ifndef _noreturn_
#if __STDC_VERSION__ >= 201112L
#define _noreturn_ _Noreturn
#else
#define _noreturn_ __attribute__((__noreturn__))
#endif
#endif

#if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#  if defined(__has_feature)
#    if __has_feature(memory_sanitizer)
#      define HAS_FEATURE_MEMORY_SANITIZER 1
#    endif
#  endif
#  if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#    define HAS_FEATURE_MEMORY_SANITIZER 0
#  endif
#endif

#if !defined(HAS_FEATURE_ADDRESS_SANITIZER)
#  ifdef __SANITIZE_ADDRESS__
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#  elif defined(__has_feature)
#    if __has_feature(address_sanitizer)
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#    endif
#  endif
#  if !defined(HAS_FEATURE_ADDRESS_SANITIZER)
#    define HAS_FEATURE_ADDRESS_SANITIZER 0
#  endif
#endif

/* Note: on GCC "no_sanitize_address" is a function attribute only, on llvm it may also be applied to global
 * variables. We define a specific macro which knows this. Note that on GCC we don't need this decorator so much, since
 * our primary usecase for this attribute is registration structures placed in named ELF sections which shall not be
 * padded, but GCC doesn't pad those anyway if AddressSanitizer is enabled. */
#if HAS_FEATURE_ADDRESS_SANITIZER && defined(__clang__)
#define _variable_no_sanitize_address_ __attribute__((__no_sanitize_address__))
#else
#define _variable_no_sanitize_address_
#endif

/* Apparently there's no has_feature() call defined to check for ubsan, hence let's define this
 * unconditionally on llvm */
#if defined(__clang__)
#define _function_no_sanitize_float_cast_overflow_ __attribute__((no_sanitize("float-cast-overflow")))
#else
#define _function_no_sanitize_float_cast_overflow_
#endif

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

#if HAVE_WSTRINGOP_TRUNCATION
#  define DISABLE_WARNING_STRINGOP_TRUNCATION                           \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wstringop-truncation\"")
#else
#  define DISABLE_WARNING_STRINGOP_TRUNCATION                           \
        _Pragma("GCC diagnostic push")
#endif

#define DISABLE_WARNING_FLOAT_EQUAL \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wfloat-equal\"")

#define DISABLE_WARNING_TYPE_LIMITS \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")

#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")

/* automake test harness */
#define EXIT_TEST_SKIP 77

/* builtins */
#if __SIZEOF_INT__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffs(x);
#elif __SIZEOF_LONG__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffsl(x);
#else
#error "neither int nor long are four bytes long?!?"
#endif

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

        /* Avoid subtraction overflow */
        if (u == 0)
                return 0;

        /* clz(0) is undefined */
        if (u == 1)
                return 1;

        /* left-shift overflow is undefined */
        if (__builtin_clzl(u - 1UL) < 1)
                return 0;

        return 1UL << (sizeof(u) * 8 - __builtin_clzl(u - 1UL));
}

static inline size_t GREEDY_ALLOC_ROUND_UP(size_t l) {
        size_t m;

        /* Round up allocation sizes a bit to some reasonable, likely larger value. This is supposed to be
         * used for cases which are likely called in an allocation loop of some form, i.e. that repetitively
         * grow stuff, for example strv_extend() and suchlike.
         *
         * Note the difference to GREEDY_REALLOC() here, as this helper operates on a single size value only,
         * and rounds up to next multiple of 2, needing no further counter.
         *
         * Note the benefits of direct ALIGN_POWER2() usage: type-safety for size_t, sane handling for very
         * small (i.e. <= 2) and safe handling for very large (i.e. > SSIZE_MAX) values. */

        if (l <= 2)
                return 2; /* Never allocate less than 2 of something.  */

        m = ALIGN_POWER2(l);
        if (m == 0) /* overflow? */
                return l;

        return m;
}

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof(""x"") - 1)

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define container_of(ptr, type, member) __container_of(UNIQ, (ptr), type, member)
#define __container_of(uniq, ptr, type, member)                         \
        ({                                                              \
                const typeof( ((type*)0)->member ) *UNIQ_T(A, uniq) = (ptr); \
                (type*)( (char *)UNIQ_T(A, uniq) - offsetof(type, member) ); \
        })

#ifdef __COVERITY__

/* Use special definitions of assertion macros in order to prevent
 * false positives of ASSERT_SIDE_EFFECT on Coverity static analyzer
 * for uses of assert_se() and assert_return().
 *
 * These definitions make expression go through a (trivial) function
 * call to ensure they are not discarded. Also use ! or !! to ensure
 * the boolean expressions are seen as such.
 *
 * This technique has been described and recommended in:
 * https://community.synopsys.com/s/question/0D534000046Yuzb/suppressing-assertsideeffect-for-functions-that-allow-for-sideeffects
 */

extern void __coverity_panic__(void);

static inline void __coverity_check__(int condition) {
        if (!condition)
                __coverity_panic__();
}

static inline int __coverity_check_and_return__(int condition) {
        return condition;
}

#define assert_message_se(expr, message) __coverity_check__(!!(expr))

#define assert_log(expr, message) __coverity_check_and_return__(!!(expr))

#else  /* ! __COVERITY__ */

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, PROJECT_FILE, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, PROJECT_FILE, __LINE__, __PRETTY_FUNCTION__), false))

#endif  /* __COVERITY__ */

#define assert_se(expr) assert_message_se(expr, #expr)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while (false)
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

#define assert_not_reached(t)                                           \
        log_assert_failed_unreachable(t, PROJECT_FILE, __LINE__, __PRETTY_FUNCTION__)

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

#define return_with_errno(r, err)                     \
        do {                                          \
                errno = abs(err);                     \
                return r;                             \
        } while (false)

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_UINT(p) ((unsigned) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define LONG_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define ULONG_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_UINT8(p) ((uint8_t) ((uintptr_t) (p)))
#define UINT8_TO_PTR(u) ((void *) ((uintptr_t) (u)))

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

#define sizeof_field(struct_type, member) sizeof(((struct_type *) 0)->member)

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
                unsigned ans = 2;                       \
                while ((_x_ /= 10) != 0)                \
                        ans++;                          \
                ans;                                    \
        })

#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)

#define SWAP_TWO(x, y) do {                        \
                typeof(x) _t = (x);                \
                (x) = (y);                         \
                (y) = (_t);                        \
        } while (false)

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))

/* Pointers range from NULL to POINTER_MAX */
#define POINTER_MAX ((void*) UINTPTR_MAX)

/* Iterates through a specified list of pointers. Accepts NULL pointers, but uses POINTER_MAX as internal marker for EOL. */
#define FOREACH_POINTER(p, x, ...)                                                       \
        for (typeof(p) *_l = (typeof(p)[]) { ({ p = x; }), ##__VA_ARGS__, POINTER_MAX }; \
             p != (typeof(p)) POINTER_MAX;                                               \
             p = *(++_l))

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

/* When func() doesn't return the appropriate type, set variable to empty afterwards */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)     \
        static inline void func##p(type *p) {                   \
                if (*p != (empty)) {                            \
                        func(*p);                               \
                        *p = (empty);                           \
                }                                               \
        }

#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)             \
        scope type *name##_ref(type *p) {                       \
                if (!p)                                         \
                        return NULL;                            \
                                                                \
                assert(p->n_ref > 0);                           \
                p->n_ref++;                                     \
                return p;                                       \
        }

#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope) \
        scope type *name##_unref(type *p) {                      \
                if (!p)                                          \
                        return NULL;                             \
                                                                 \
                assert(p->n_ref > 0);                            \
                p->n_ref--;                                      \
                if (p->n_ref > 0)                                \
                        return NULL;                             \
                                                                 \
                return free_func(p);                             \
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

#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);

/* A macro to force copying of a variable from memory. This is useful whenever we want to read something from
 * memory and want to make sure the compiler won't optimize away the destination variable for us. It's not
 * supposed to be a full CPU memory barrier, i.e. CPU is still allowed to reorder the reads, but it is not
 * allowed to remove our local copies of the variables. We want this to work for unaligned memory, hence
 * memcpy() is great for our purposes. */
#define READ_NOW(x)                                                     \
        ({                                                              \
                typeof(x) _copy;                                        \
                memcpy(&_copy, &(x), sizeof(_copy));                    \
                asm volatile ("" : : : "memory");                       \
                _copy;                                                  \
        })

static inline size_t size_add(size_t x, size_t y) {
        return y >= SIZE_MAX - x ? SIZE_MAX : x + y;
}

#include "log.h"
