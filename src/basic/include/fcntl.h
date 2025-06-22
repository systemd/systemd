/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <fcntl.h>

/* This is defined since glibc-2.41. */
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY 1027
#endif

/* This is defined since glibc-2.39. */
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC     0x0020  /* prevent chmod modifying exec bits */
#endif

/* So O_LARGEFILE is generally implied by glibc, and defined to zero hence, because we only build in LFS
 * mode. However, when invoking fcntl(F_GETFL) the flag is ORed into the result anyway — glibc does not mask
 * it away. Which sucks. Let's define the actual value here, so that we can mask it ourselves.
 *
 * The precise definition is arch specific, so we use the values defined in the kernel (note that some
 * are hexa and others are octal; duplicated as-is from the kernel definitions):
 * - alpha, arm, arm64, m68k, mips, parisc, powerpc, sparc: each has a specific value;
 * - others: they use the "generic" value (defined in include/uapi/asm-generic/fcntl.h) */
#if O_LARGEFILE == 0
#undef O_LARGEFILE
#if defined(__alpha__) || defined(__arm__) || defined(__aarch64__) || defined(__m68k__)
#define O_LARGEFILE 0400000
#elif defined(__mips__)
#define O_LARGEFILE 0x2000
#elif defined(__parisc__) || defined(__hppa__)
#define O_LARGEFILE 000004000
#elif defined(__powerpc__)
#define O_LARGEFILE 0200000
#elif defined(__sparc__)
#define O_LARGEFILE 0x40000
#else
#define O_LARGEFILE 00100000
#endif
#endif

/* This is defined since glibc-2.39. */
#ifndef AT_HANDLE_FID
#define AT_HANDLE_FID AT_REMOVEDIR
#endif

/* On musl, O_ACCMODE is defined as (03|O_SEARCH), unlike glibc which defines it as
 * (O_RDONLY|O_WRONLY|O_RDWR). Additionally, O_SEARCH is simply defined as O_PATH. This changes the behaviour
 * of O_ACCMODE in certain situations, which we don't want. This definition is copied from glibc and works
 * around the problems with musl's definition. */
#undef O_ACCMODE
#define O_ACCMODE (O_RDONLY|O_WRONLY|O_RDWR)
