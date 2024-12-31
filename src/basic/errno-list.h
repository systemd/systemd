/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/*
 * MAX_ERRNO is defined as 4095 in linux/err.h
 * We use the same value here.
 */
#define ERRNO_MAX 4095

#if HAVE_STRERRORNAME_NP
static inline const char* errno_to_name(int id) {
        if (id == 0) /* To stay in line with our own impl */
                return NULL;

        return strerrorname_np(abs(id));
}
#else
const char* errno_to_name(int id);
#endif

int errno_from_name(const char *name);

static inline bool errno_is_valid(int n) {
        return n > 0 && n <= ERRNO_MAX;
}
