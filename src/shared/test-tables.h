/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string-util.h"

#define _test_table(name, lookup, reverse, size, sparse)                \
        for (int64_t _i = -EINVAL, _boring = 0; _i < size + 1; _i++) {  \
                const char* _val;                                       \
                int64_t _rev;                                           \
                                                                        \
                _val = lookup(_i);                                      \
                if (_val) {                                             \
                        _rev = reverse(_val);                           \
                        _boring = 0;                                    \
                } else {                                                \
                        _rev = reverse("--no-such--value----");         \
                        _boring += _i >= 0;                             \
                }                                                       \
                if (_boring == 0 || _i == size)                         \
                        printf("%s: %" PRIi64 " → %s → %" PRIi64 "\n", name, _i, strnull(_val), _rev); \
                else if (_boring == 1)                                  \
                        printf("%*s  ...\n", (int) strlen(name), "");   \
                                                                        \
                if (_i >= 0 && _i < size) {                             \
                        if (sparse)                                     \
                                assert_se(_rev == _i || _rev == -EINVAL); \
                        else                                            \
                                assert_se(_val && _rev == _i);          \
                } else                                                  \
                        assert_se(!_val && _rev == -EINVAL);            \
        }

#define test_table(lower, upper)                                        \
        _test_table(STRINGIFY(lower), lower##_to_string, lower##_from_string, _##upper##_MAX, false)

#define test_table_sparse(lower, upper)                                 \
        _test_table(STRINGIFY(lower), lower##_to_string, lower##_from_string, _##upper##_MAX, true)
