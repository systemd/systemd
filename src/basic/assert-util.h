/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "assert-fundamental.h" /* IWYU pragma: export */

/* Logging for various assertions */

void log_set_assert_return_is_critical(bool b);
bool log_get_assert_return_is_critical(void) _pure_;

void log_assert_failed_return(const char *text, const char *file, int line, const char *func);

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, PROJECT_FILE, __LINE__, __func__), false))

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
