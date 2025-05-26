/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

const char* errno_to_name(int id);

int errno_from_name(const char *name) _const_;

static inline bool errno_is_valid(int n) {
        return n > 0 && n <= ERRNO_MAX;
}
