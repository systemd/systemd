/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h" /* IWYU pragma: export */

/* Logging for various assertions */

bool log_get_assert_return_is_critical(void) _weak_ _pure_;

void log_assert_failed_return(const char *text, const char *file, int line, const char *func);

#define assert_log(expr)                                                \
        (_likely_(expr) ?                                               \
         true :                                                         \
         (log_assert_failed_return(#expr, PROJECT_FILE, __LINE__, __func__), false))

#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr))                                  \
                        return (r);                                     \
        } while (false)

#define assert_return_errno(expr, r, err)                               \
        do {                                                            \
                if (!assert_log(expr)) {                                \
                        errno = err;                                    \
                        return (r);                                     \
                }                                                       \
        } while (false)
