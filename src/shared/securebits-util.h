/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/securebits.h>

#include "shared-forward.h"

int secure_bits_to_strv(int i, char ***ret);
DECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK(secure_bits, int);

static inline bool secure_bits_is_valid(int i) {
        return ((SECURE_ALL_BITS | SECURE_ALL_LOCKS) & i) == i;
}

static inline int secure_bits_to_string_alloc_with_check(int n, char **s) {
        if (!secure_bits_is_valid(n))
                return -EINVAL;

        return secure_bits_to_string_alloc(n, s);
}
