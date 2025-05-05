/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward-fundamental.h"

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
