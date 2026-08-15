/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>

#include "libc-shim.h"

/* On 32-bit architectures built with _TIME_BITS=64, glibc renames epoll_pwait2() to
 * __epoll_pwait2_time64 via __asm__() in <sys/epoll.h> so the linker picks the variant whose
 * struct timespec ABI matches our 64-bit time_t. dlsym() can't see that header-level rename, so
 * we have to spell out the right name here, otherwise we'd silently dispatch a 64-bit timespec to
 * the legacy 32-bit-time_t entry point. */
#ifdef __USE_TIME_BITS64
DEFINE_LIBC_ERRNO_SHIM_NAMED(epoll_pwait2, "__epoll_pwait2_time64", int,
                             int, fd,
                             struct epoll_event *, events,
                             int, maxevents,
                             const struct timespec *, timeout,
                             const sigset_t *, sigmask)
#else
DEFINE_LIBC_ERRNO_SHIM(epoll_pwait2, int,
                       int, fd,
                       struct epoll_event *, events,
                       int, maxevents,
                       const struct timespec *, timeout,
                       const sigset_t *, sigmask)
#endif
