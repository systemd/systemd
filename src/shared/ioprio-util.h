/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/ioprio.h>         /* IWYU pragma: export */

#include "forward.h"

static inline int ioprio_prio_class(int value) {
        return IOPRIO_PRIO_CLASS(value);
}

static inline int ioprio_prio_data(int value) {
        return IOPRIO_PRIO_DATA(value);
}

static inline int ioprio_prio_value(int class, int data) {
        return IOPRIO_PRIO_VALUE_HINT(class, IOPRIO_PRIO_LEVEL(data), IOPRIO_PRIO_HINT(data));
}

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

static inline bool ioprio_class_is_valid(int i) {
        return IN_SET(i, IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE);
}

static inline bool ioprio_priority_is_valid(int i) {
        return i >= 0 && i < IOPRIO_NR_LEVELS;
}

int ioprio_parse_priority(const char *s, int *ret);

/* IOPRIO_CLASS_NONE with any prio value is another way to say IOPRIO_CLASS_BE with level 4. Encode that in a
 * proper macro. */
#define IOPRIO_DEFAULT_CLASS_AND_PRIO ioprio_prio_value(IOPRIO_CLASS_BE, 4)

static inline int ioprio_normalize(int v) {
        /* Converts IOPRIO_CLASS_NONE to what it actually means */
        return ioprio_prio_class(v) == IOPRIO_CLASS_NONE ? IOPRIO_DEFAULT_CLASS_AND_PRIO : v;
}
