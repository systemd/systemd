/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* libucontext.h in freestanding mode and sys/ucontext.h both define REG_R8 which ends up conflicting if both
 * are included in the same translation unit. Unfortunately, we cannot simply not include sys/ucontext.h when
 * building with libucontext as sys/ucontext.h is unconditionally included by signal.h, so we override
 * sys/ucontext.h to avoid conflicts. */

/* Since we don't have a way to check whether libucontext was built in freestanding mode or not, we check for
 * glibc as a proxy since glibc-based distributions shipping libucontext should be building it in
 * freestanding mode. */

#if HAVE_LIBUCONTEXT && defined(__GLIBC__)
#include <libucontext/libucontext.h>    /* IWYU pragma: export */

typedef libucontext_ucontext_t ucontext_t;
#else
#include_next <sys/ucontext.h>          /* IWYU pragma: export */
#endif
