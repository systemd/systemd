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
