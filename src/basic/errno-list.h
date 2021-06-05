/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
/*
 * MAX_ERRNO is defined as 4095 in linux/err.h
 * We use the same value here.
 */
#define ERRNO_MAX 4095

const char *errno_to_name(int id);
int errno_from_name(const char *name);
static inline bool errno_is_valid(int n) {
        return n > 0 && n <= ERRNO_MAX;
}
