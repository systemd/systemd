/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <limits.h>        /* IWYU pragma: export */

#include <assert.h>
#include <sys/types.h>

/* When this override is first on the include search path (-isystem
 * src/include/musl), '#include_next <limits.h>' reaches the compiler's own
 * <limits.h>, which uses a two-pass '#include_next' sequence (guarded by
 * _GCC_LIMITS_H_ via <syslimits.h>) to pull in the C library's <limits.h>.
 * With this override occupying the first search-path slot, its own
 * '#include_next' shifts the position the compiler's second-pass
 * '#include_next' resolves from, so the chain overshoots musl's <limits.h>
 * and never includes it. The POSIX limits musl defines in its
 * feature-test-macro guarded section are therefore missing. This differs
 * from the sibling overrides in this directory (e.g. <stdlib.h>, <string.h>)
 * because the compiler ships its own <limits.h> but not those; reordering
 * the -isystem paths does not help.
 *
 * Provide the POSIX limits systemd relies on, using musl's canonical values
 * (see musl's include/limits.h). Each is #ifndef-guarded so glibc, and any
 * toolchain whose '#include_next' does reach musl's <limits.h>, are
 * unaffected. */
#ifndef NAME_MAX
#  define NAME_MAX 255
#endif
#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif
#ifndef HOST_NAME_MAX
#  define HOST_NAME_MAX 255
#endif
#ifndef LINE_MAX
#  define LINE_MAX 4096
#endif
#ifndef IOV_MAX
#  define IOV_MAX 1024
#endif
#ifndef PIPE_BUF
#  define PIPE_BUF 4096
#endif
#ifndef PTHREAD_STACK_MIN
#  define PTHREAD_STACK_MIN 2048
#endif
#ifndef _POSIX_PATH_MAX
#  define _POSIX_PATH_MAX 256
#endif
#ifndef _POSIX_TZNAME_MAX
#  define _POSIX_TZNAME_MAX 6
#endif

/* musl defines SSIZE_MAX as LONG_MAX, so its type is always long. However, on 32-bit architectures, musl
 * defines ssize_t as int. Strictly speaking, this is not a bug in musl. POSIX only requires SSIZE_MAX to
 * evaluate to the maximum value representable by ssize_t; it does not require SSIZE_MAX itself to have type
 * ssize_t. However, our code assumes that SSIZE_MAX has type ssize_t, as is the case with glibc. Cast the
 * value explicitly so that SSIZE_MAX has type ssize_t. The assert is guarded because SSIZE_MAX is only
 * visible when <limits.h> actually supplied it (see above). */
#ifdef SSIZE_MAX
static_assert(SSIZE_MAX == LONG_MAX, "");
#  undef SSIZE_MAX
#endif
#define SSIZE_MAX ((ssize_t) LONG_MAX)
