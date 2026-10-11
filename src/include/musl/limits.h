/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* GCC introduces a spurious, tricky inclusion cycle:
 *    GCC's limits.h
 *      -> GCC's syslimits.h
 *         -> GCC's limits.h (again!!!)
 *            -> glibc/musl's limits.h
 *               -> define POSIX defines
 *      -> define ISO C defines
 * This works only when GCC's limits.h is included first, but a user override breaks the cycle. Hence, we
 * need to manually achieve the cycle here. If GCC is not used (e.g., Clang), then including the compiler's
 * limits.h twice should be redundant but harmless. */

/* First, get the POSIX defines from glibc/musl's limits.h. When the two macros below are defined, GCC's
 * limits.h includes the next limits.h, that is, one from glibc/musl. */
#define _GCC_LIMITS_H_
#define _GCC_NEXT_LIMITS_H
#include_next <limits.h>        /* IWYU pragma: export */
#undef _GCC_NEXT_LIMITS_H
#undef _GCC_LIMITS_H_

/* Next, get the ISO C defines from GCC's limits.h. */
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
