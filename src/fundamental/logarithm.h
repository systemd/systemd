/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/* Note: log2(0) == log2(1) == 0 here and below. */

#define CONST_LOG2ULL(x) ((x) > 1 ? (unsigned) __builtin_clzll(x) ^ 63U : 0)
#define NONCONST_LOG2ULL(x) ({                                     \
                unsigned long long _x = (x);                       \
                _x > 1 ? (unsigned) __builtin_clzll(_x) ^ 63U : 0; \
        })
#define LOG2ULL(x) __builtin_choose_expr(__builtin_constant_p(x), CONST_LOG2ULL(x), NONCONST_LOG2ULL(x))

static inline unsigned log2u64(uint64_t x) {
#if __SIZEOF_LONG_LONG__ == 8
        return LOG2ULL(x);
#else
#  error "Wut?"
#endif
}

static inline unsigned u32ctz(uint32_t n) {
#if __SIZEOF_INT__ == 4
        return n != 0 ? __builtin_ctz(n) : 32;
#else
#  error "Wut?"
#endif
}

#define popcount(n)                                             \
        _Generic((n),                                           \
                 unsigned char: __builtin_popcount(n),          \
                 unsigned short: __builtin_popcount(n),         \
                 unsigned: __builtin_popcount(n),               \
                 unsigned long: __builtin_popcountl(n),         \
                 unsigned long long: __builtin_popcountll(n))

#define CONST_LOG2U(x) ((x) > 1 ? __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1 : 0)
#define NONCONST_LOG2U(x) ({                                             \
                unsigned _x = (x);                                       \
                _x > 1 ? __SIZEOF_INT__ * 8 - __builtin_clz(_x) - 1 : 0; \
        })
#define LOG2U(x) __builtin_choose_expr(__builtin_constant_p(x), CONST_LOG2U(x), NONCONST_LOG2U(x))

static inline unsigned log2i(int x) {
        return LOG2U(x);
}

static inline unsigned log2u(unsigned x) {
        return LOG2U(x);
}

static inline unsigned log2u_round_up(unsigned x) {
        if (x <= 1)
                return 0;

        return log2u(x - 1) + 1;
}
