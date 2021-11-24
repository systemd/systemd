/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "missing_ioprio.h"

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

static inline bool ioprio_class_is_valid(int i) {
        return IN_SET(i, IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE);
}

static inline bool ioprio_priority_is_valid(int i) {
        return i >= 0 && i < IOPRIO_BE_NR;
}

int ioprio_parse_priority(const char *s, int *ret);

/* IOPRIO_CLASS_NONE with any prio value is another way to say IOPRIO_CLASS_BE with level 4. Encode that in a
 * proper macro. */
#define IOPRIO_DEFAULT_CLASS_AND_PRIO ioprio_prio_value(IOPRIO_CLASS_BE, 4)

static inline int ioprio_normalize(int v) {
        /* Converts IOPRIO_CLASS_NONE to what it actually means */
        return ioprio_prio_class(v) == IOPRIO_CLASS_NONE ? IOPRIO_DEFAULT_CLASS_AND_PRIO : v;
}
