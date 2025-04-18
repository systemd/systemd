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
