/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>              /* IWYU pragma: keep */
#include <linux/time_types.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <unistd.h>

int missing_epoll_pwait2(
                int epfd,
                struct epoll_event *events,
                int maxevents,
                const struct timespec *timeout,
                const sigset_t *sigmask) {

        /* We intentionally reject non-NULL sigmask to avoid depending on the architecture-specific kernel
         * sigset_t size. If sigmask support is ever added, the correct sigsetsize must be passed to the
         * syscall. */
        if (sigmask)
                return -ENOSYS;

        /* Convert struct timespec to struct __kernel_timespec, as they may differ. */
        struct __kernel_timespec t, *p = NULL;
        if (timeout) {
                t = (struct __kernel_timespec) {
                        .tv_sec = (__kernel_time64_t) timeout->tv_sec,
                        .tv_nsec = (long long) timeout->tv_nsec,
                };
                p = &t;
        }

        return syscall(__NR_epoll_pwait2, epfd, events, maxevents, p, /* sigmask= */ NULL, /* sigsetsize= */ 0);
}
