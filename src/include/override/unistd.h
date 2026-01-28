/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <unistd.h>        /* IWYU pragma: export */

#if !HAVE_PIVOT_ROOT
int missing_pivot_root(const char *new_root, const char *put_old);
#  define pivot_root missing_pivot_root
#endif
