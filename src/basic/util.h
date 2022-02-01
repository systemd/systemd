/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "macro.h"

extern int saved_argc;
extern char **saved_argv;

static inline void save_argc_argv(int argc, char **argv) {

        /* Protect against CVE-2021-4034 style attacks */
        assert_se(argc > 0);
        assert_se(argv);
        assert_se(argv[0]);

        saved_argc = argc;
        saved_argv = argv;
}

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

bool in_initrd(void);
void in_initrd_force(bool value);

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

int container_get_leader(const char *machine, pid_t *pid);

int version(void);

void disable_coredumps(void);
