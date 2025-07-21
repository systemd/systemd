/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* glibc defines AT_FDCWD as -100, but musl defines it as (-100). Hence, musl's fcntl.h conflicts with
 * forward.h. To avoid the conflict, here temporary undef AT_FDCWD before including fcntl.h. */
#ifdef AT_FDCWD
#undef AT_FDCWD
#endif

#include_next <fcntl.h>

/* Then, undef AT_FDCWD by fcntl.h and redefine it as consistent with forward.h */
#undef AT_FDCWD
#define AT_FDCWD -100
