/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "macro.h"

extern int saved_argc;
extern char **saved_argv;

static inline void save_argc_argv(int argc, char **argv) {
        saved_argc = argc;
        saved_argv = argv;
}

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

bool in_initrd(void);
void in_initrd_force(bool value);

int on_ac_power(void);

#define LOG2U64(x) (x > 1 ? (unsigned) __builtin_clzll(x) ^ 63U : 0)
static inline unsigned log2u64(uint64_t x) {
#if __SIZEOF_LONG_LONG__ == 8
        return LOG2U64(x);
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

#define LOG2I(x) (__SIZEOF_INT__ * 8 - __builtin_clz(x) - 1)
static inline unsigned log2i(int x) {
        assert(x > 0);

        return LOG2I(x);
}

#define LOG2U(x) (sizeof(unsigned) * 8 - __builtin_clz(x) - 1)
static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return LOG2U(x);
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

int container_get_leader(const char *machine, pid_t *pid);

int version(void);

void disable_coredumps(void);
