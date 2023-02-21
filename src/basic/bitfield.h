/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* Bit index(es) (0-based) to mask (of specified type). Assertion failure if (any) index is out of range. */
#define INDEX_TO_MASK(type, ...)                                        \
        _INDEX_TO_MASK(type, UNIQ_T(_mask_, UNIQ), UNIQ_T(_i_, UNIQ), ##__VA_ARGS__)
#define _INDEX_TO_MASK(type, _mask_, _i_, ...)                          \
        ({                                                              \
                type _mask_ = 0;                                        \
                assert(sizeof(type) <= sizeof(unsigned long long));     \
                VA_ARGS_FOREACH(_i_, size_t, __VA_ARGS__) {             \
                        assert(_i_ < sizeof(type) * 8);                 \
                        SET_FLAG(_mask_, ((type)1) << _i_, true);       \
                }                                                       \
                _mask_;                                                 \
        })

/* Same as the FLAG macros, but accept bit index(es) instead of a mask. Index is 0-based. Assertion failure
 * if index is out of range. */
#define SET_BIT(bits, ...) SET_FLAG(bits, INDEX_TO_MASK(typeof(bits), ##__VA_ARGS__), true)
#define CLEAR_BIT(bits, ...) SET_FLAG(bits, INDEX_TO_MASK(typeof(bits), ##__VA_ARGS__), false)
#define BITS_SET(bits, ...) FLAGS_SET(bits, INDEX_TO_MASK(typeof(bits), ##__VA_ARGS__))

/* Iterate through each set bit. Index is 0-based and type int. */
#define BIT_FOREACH(index, bits) _BIT_FOREACH(index, bits, UNIQ_T(_last_, UNIQ))
#define _BIT_FOREACH(index, bits, _last_)                               \
        for (int _last_ = -1, index; (index = BIT_NEXT_SET(bits, _last_)) >= 0; _last_ = index)

/* Find the next set bit after 0-based index 'prev'. Result is 0-based index of next set bit, or -1 if no
 * more bits are set. */
#define BIT_FIRST_SET(bits) BIT_NEXT_SET(bits, -1)
#define BIT_NEXT_SET(bits, prev) _BIT_NEXT_SET(bits, prev, UNIQ_T(_prev_, UNIQ))
#define _BIT_NEXT_SET(bits, prev, _prev_)                               \
        ({                                                              \
                int _prev_ = (prev);                                    \
                _prev_ + 1 == (int)sizeof(bits) * 8                     \
                        ? -1 /* Prev index was msb. */                  \
                        : __BIT_NEXT_SET(bits, _prev_, UNIQ_T(_next_, UNIQ)); \
        })
#define __BIT_NEXT_SET(bits, _prev_, _next_)                            \
        ({                                                              \
                int _next_ = __builtin_ffsll(((unsigned long long)(bits)) >> (_prev_ + 1)); \
                _next_ == 0                                             \
                        ? -1 /* No more bits set. */                    \
                        : _prev_ + _next_;                              \
        })
