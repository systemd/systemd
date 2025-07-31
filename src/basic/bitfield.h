/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Bit index (0-based) to mask of specified type. Assertion failure if index is out of range. */
#define _INDEX_TO_MASK(type, i, uniq)                                   \
        ({                                                              \
                int UNIQ_T(_i, uniq) = (i);                             \
                assert(UNIQ_T(_i, uniq) >= 0);                          \
                assert(UNIQ_T(_i, uniq) < (int)sizeof(type) * 8);       \
                ((type)1) << UNIQ_T(_i, uniq);                          \
        })
#define INDEX_TO_MASK(type, i)                                          \
        ({                                                              \
                assert_cc(sizeof(type) <= sizeof(unsigned long long));  \
                assert_cc(__builtin_choose_expr(__builtin_constant_p(i), i, 0) < (int)(sizeof(type) * 8)); \
                __builtin_choose_expr(__builtin_constant_p(i),          \
                                      ((type)1) << (i),                 \
                                      _INDEX_TO_MASK(type, i, UNIQ));   \
        })

/* Builds a mask of specified type with multiple bits set. Note the result will not be constant, even if all
 * indexes are constant. */
#define INDEXES_TO_MASK(type, ...)                              \
        UNIQ_INDEXES_TO_MASK(type, UNIQ, ##__VA_ARGS__)
#define UNIQ_INDEXES_TO_MASK(type, uniq, ...)                           \
        ({                                                              \
                typeof(type) UNIQ_T(_mask, uniq) = (type)0;             \
                int UNIQ_T(_i, uniq);                                   \
                FOREACH_ARGUMENT(UNIQ_T(_i, uniq), ##__VA_ARGS__)       \
                        UNIQ_T(_mask, uniq) |= INDEX_TO_MASK(type, UNIQ_T(_i, uniq)); \
                UNIQ_T(_mask, uniq);                                    \
        })

/* Same as the FLAG macros, but accept a 0-based bit index instead of a mask. Results in assertion failure if
 * index is out of range for the type. */
#define SET_BIT(bits, i) SET_FLAG(bits, INDEX_TO_MASK(typeof(bits), i), true)
#define CLEAR_BIT(bits, i) SET_FLAG(bits, INDEX_TO_MASK(typeof(bits), i), false)
#define BIT_SET(bits, i) FLAGS_SET(bits, INDEX_TO_MASK(typeof(bits), i))

/* As above, but accepts multiple indexes. Note the result will not be constant, even if all indexes are
 * constant. */
#define SET_BITS(bits, ...) SET_FLAG(bits, INDEXES_TO_MASK(typeof(bits), ##__VA_ARGS__), true)
#define CLEAR_BITS(bits, ...) SET_FLAG(bits, INDEXES_TO_MASK(typeof(bits), ##__VA_ARGS__), false)
#define BITS_SET(bits, ...) FLAGS_SET(bits, INDEXES_TO_MASK(typeof(bits), ##__VA_ARGS__))

/* Iterate through each set bit. Index is 0-based and type int. */
#define BIT_FOREACH(index, bits) _BIT_FOREACH(index, bits, UNIQ)
#define _BIT_FOREACH(index, bits, uniq)                                 \
        for (int UNIQ_T(_last, uniq) = -1, index;                       \
             (index = BIT_NEXT_SET(bits, UNIQ_T(_last, uniq))) >= 0;    \
             UNIQ_T(_last, uniq) = index)

/* Find the next set bit after 0-based index 'prev'. Result is 0-based index of next set bit, or -1 if no
 * more bits are set. */
#define BIT_FIRST_SET(bits) BIT_NEXT_SET(bits, -1)
#define BIT_NEXT_SET(bits, prev)                        \
        UNIQ_BIT_NEXT_SET(bits, prev, UNIQ)
#define UNIQ_BIT_NEXT_SET(bits, prev, uniq)                             \
        ({                                                              \
                typeof(bits) UNIQ_T(_bits, uniq) = (bits);              \
                int UNIQ_T(_prev, uniq) = (prev);                       \
                int UNIQ_T(_next, uniq);                                \
                _BIT_NEXT_SET(UNIQ_T(_bits, uniq),                      \
                              UNIQ_T(_prev, uniq),                      \
                              UNIQ_T(_next, uniq));                     \
        })
#define _BIT_NEXT_SET(bits, prev, next)                                 \
        ((int)(prev + 1) == (int)sizeof(bits) * 8                       \
         ? -1 /* Prev index was msb. */                                 \
         : ((next = __builtin_ffsll(((unsigned long long)(bits)) >> (prev + 1))) == 0 \
            ? -1 /* No more bits set. */                                \
            : prev + next))
