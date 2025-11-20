/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !SD_BOOT
#  include <assert.h>
#endif

#include "macro-fundamental.h"

#if SD_BOOT
        _noreturn_ void efi_assert(const char *expr, const char *file, unsigned line, const char *function);

        #ifdef NDEBUG
                #define assert(expr) ({ if (!(expr)) __builtin_unreachable(); })
                #define assert_not_reached() __builtin_unreachable()
        #else
                #define assert(expr) ({ _likely_(expr) ? VOID_0 : efi_assert(#expr, __FILE__, __LINE__, __func__); })
                #define assert_not_reached() efi_assert("Code should not be reached", __FILE__, __LINE__, __func__)
        #endif
        #define assert_se(expr) ({ _likely_(expr) ? VOID_0 : efi_assert(#expr, __FILE__, __LINE__, __func__); })
#else

_noreturn_ void log_assert_failed(const char *text, const char *file, int line, const char *func);
_noreturn_ void log_assert_failed_unreachable(const char *file, int line, const char *func);

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

#define assert_log(expr) __coverity_check_and_return__(!!(expr))

#else  /* ! __COVERITY__ */

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, PROJECT_FILE, __LINE__, __func__); \
        } while (false)

#endif  /* __COVERITY__ */

#define assert_se(expr) assert_message_se(expr, #expr)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) ({ if (!(expr)) __builtin_unreachable(); })
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

#define assert_not_reached()                                            \
        log_assert_failed_unreachable(PROJECT_FILE, __LINE__, __func__)

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
