/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sched.h>

/* This is for avoiding multiple evaluations in musl's __CPU_op_S() macro. */

#undef __CPU_op_S
#undef CPU_SET_S
#undef CPU_CLR_S
#undef CPU_ISSET_S
#undef CPU_SET
#undef CPU_CLR
#undef CPU_ISSET

#define __CPU_op_S(i, size, set, op) \
        ({                           \
                typeof(i) _i = (i);                                     \
                                                                        \
                _i / 8U >= (size) ? 0 :                                 \
                        (((unsigned long*) (set))[_i / 8 / sizeof(long)] op (1UL << (_i % (8 * sizeof(long))))); \
        })

#define CPU_SET_S(i, size, set) __CPU_op_S(i, size, set, |=)
#define CPU_CLR_S(i, size, set) __CPU_op_S(i, size, set, &=~)
#define CPU_ISSET_S(i, size, set) __CPU_op_S(i, size, set, &)

#define CPU_SET(i, set) CPU_SET_S(i, sizeof(cpu_set_t), set)
#define CPU_CLR(i, set) CPU_CLR_S(i, sizeof(cpu_set_t), set)
#define CPU_ISSET(i, set) CPU_ISSET_S(i, sizeof(cpu_set_t), set)
