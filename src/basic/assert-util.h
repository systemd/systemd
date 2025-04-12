/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h"
#include "macro.h"

/* Logging for various assertions */

void log_set_assert_return_is_critical(bool b);
bool log_get_assert_return_is_critical(void) _pure_;

_noreturn_ void log_assert_failed(const char *text, const char *file, int line, const char *func);
_noreturn_ void log_assert_failed_unreachable(const char *file, int line, const char *func);
void log_assert_failed_return(const char *text, const char *file, int line, const char *func);

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
                        log_assert_failed(message, PROJECT_FILE, __LINE__, __func__); \
        } while (false)

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, PROJECT_FILE, __LINE__, __func__), false))

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
