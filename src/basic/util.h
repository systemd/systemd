/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdint.h>

#include "macro.h"

static inline const char* yes_no(bool b) {
        return b ? "yes" : "no";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

static inline const char* enable_disable(bool b) {
        return b ? "enable" : "disable";
}

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

static inline unsigned u64log2(uint64_t n) {
#if __SIZEOF_LONG_LONG__ == 8
        return (n > 1) ? (unsigned) __builtin_clzll(n) ^ 63U : 0;
#else
#error "Wut?"
#endif
}

static inline unsigned u32ctz(uint32_t n) {
#if __SIZEOF_INT__ == 4
        return n != 0 ? __builtin_ctz(n) : 32;
#else
#error "Wut?"
#endif
}

static inline unsigned log2i(int x) {
        assert(x > 0);

        return __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return sizeof(unsigned) * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

int container_get_leader(const char *machine, pid_t *pid);

int version(void);

int str_verscmp(const char *s1, const char *s2);

void disable_coredumps(void);
