/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <linux/bpf_insn.h>     /* IWYU pragma: export */

/* defined in linux/filter.h */
/* Unconditional jumps, goto pc + off16 */
#define BPF_JMP_A(OFF)                                          \
        ((struct bpf_insn) {                                    \
                .code  = BPF_JMP | BPF_JA,                      \
                .dst_reg = 0,                                   \
                .src_reg = 0,                                   \
                .off   = OFF,                                   \
                .imm   = 0 })
