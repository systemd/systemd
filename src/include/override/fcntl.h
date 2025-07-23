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

/* This is defined since glibc-2.41. */
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY 1027
#endif

/* This is defined since glibc-2.39. */
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC     0x0020  /* prevent chmod modifying exec bits */
#endif

/* This is defined since glibc-2.39. */
#ifndef AT_HANDLE_FID
#define AT_HANDLE_FID AT_REMOVEDIR
#endif
