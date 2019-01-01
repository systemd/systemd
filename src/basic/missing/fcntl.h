/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <fcntl.h>

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

/* The precise definition of __O_TMPFILE is arch specific; use the
 * values defined by the kernel (note: some are hexa, some are octal,
 * duplicated as-is from the kernel definitions):
 * - alpha, parisc, sparc: each has a specific value;
 * - others: they use the "generic" value.
 */

#ifndef __O_TMPFILE
#if defined(__alpha__)
#define __O_TMPFILE     0100000000
#elif defined(__parisc__) || defined(__hppa__)
#define __O_TMPFILE     0400000000
#elif defined(__sparc__) || defined(__sparc64__)
#define __O_TMPFILE     0x2000000
#else
#define __O_TMPFILE     020000000
#endif
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif
