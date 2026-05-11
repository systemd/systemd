/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <fcntl.h>         /* IWYU pragma: export */
#include <linux/openat2.h>      /* IWYU pragma: export */
#include <stddef.h>

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

/* This is defined since glibc-2.42. */
#ifndef AT_HANDLE_MNT_ID_UNIQUE
#define AT_HANDLE_MNT_ID_UNIQUE 0x001  /* Return the u64 unique mount ID. */
#endif

/* Defined since glibc-2.42.
 * Supported since kernel v5.6 (fddb5d430ad9fa91b49b1d34d0202ffe2fa0e179). */
#if !HAVE_OPENAT2
int missing_openat2(int dfd, const char *filename, const struct open_how *how, size_t usize);
#  define openat2 missing_openat2
#endif
