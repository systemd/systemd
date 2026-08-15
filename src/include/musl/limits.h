/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <limits.h>        /* IWYU pragma: export */

#include <assert.h>
#include <sys/types.h>

/* musl defines SSIZE_MAX as LONG_MAX, so its type is always long. However, on 32-bit architectures, musl
 * defines ssize_t as int. Strictly speaking, this is not a bug in musl. POSIX only requires SSIZE_MAX to
 * evaluate to the maximum value representable by ssize_t; it does not require SSIZE_MAX itself to have type
 * ssize_t. However, our code assumes that SSIZE_MAX has type ssize_t, as is the case with glibc. Cast the
 * value explicitly so that SSIZE_MAX has type ssize_t. */
static_assert(SSIZE_MAX == LONG_MAX, "");
#undef SSIZE_MAX
#define SSIZE_MAX ((ssize_t) LONG_MAX)
