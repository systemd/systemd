/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "securebits.h"

int secure_bits_to_string_alloc(int i, char **s);
int secure_bits_from_string(const char *s);

static inline bool secure_bits_is_valid(int i) {
        return ((SECURE_ALL_BITS | SECURE_ALL_LOCKS) & i) == i;
}

static inline int secure_bits_to_string_alloc_with_check(int n, char **s) {
        if (!secure_bits_is_valid(n))
                return -EINVAL;

        return secure_bits_to_string_alloc(n, s);
}
