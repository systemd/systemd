/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/epoll.h>     /* IWYU pragma: export */

/* epoll_pwait2() was added in glibc 2.35 and is currently unavailable in musl.
 * Call the syscall directly instead of relying on the libc wrapper. */
int missing_epoll_pwait2(
                int fd,
                struct epoll_event *events,
                int maxevents,
                const struct timespec *timeout,
                const sigset_t *sigmask);
