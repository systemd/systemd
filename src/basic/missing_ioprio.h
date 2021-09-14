/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Match values uses by the kernel internally, as no public header seems to exist. */

#ifndef IOPRIO_N_CLASSES
#  define IOPRIO_N_CLASSES 8
#endif

#ifndef IOPRIO_BE_NR
#  define IOPRIO_BE_NR 8
#endif

#define IOPRIO_CLASS_NONE 0
#define IOPRIO_CLASS_RT   1
#define IOPRIO_CLASS_BE   2
#define IOPRIO_CLASS_IDLE 3

#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_WHO_PGRP    2
#define IOPRIO_WHO_USER    3

#define IOPRIO_BITS        16
#define IOPRIO_N_CLASSES    8
#define IOPRIO_CLASS_SHIFT 13

static inline int ioprio_prio_class(int value) {
        return value >> IOPRIO_CLASS_SHIFT;
}

static inline int ioprio_prio_data(int value) {
        return value & ((1 << IOPRIO_CLASS_SHIFT) - 1);
}

static inline int ioprio_prio_value(int class, int data) {
        return (class << IOPRIO_CLASS_SHIFT) | data;
}
