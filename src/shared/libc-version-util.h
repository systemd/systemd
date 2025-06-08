/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#ifdef __GLIBC__
#  include <gnu/libc-version.h>
#endif

static inline const char* get_libc_version(void) {
#ifdef __GLIBC__
        return gnu_get_libc_version();
#else
        return NULL;
#endif
}
