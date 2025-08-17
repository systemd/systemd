/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_CLOSE_RANGE
int missing_close_range(unsigned first_fd, unsigned end_fd, unsigned flags) {
        /* Kernel-side the syscall expects fds as unsigned integers (just like close() actually), while
         * userspace exclusively uses signed integers for fds. glibc chose to expose it 1:1 however, hence we
         * do so here too, even if we end up passing signed fds to it most of the time. */
        return syscall(__NR_close_range, first_fd, end_fd, flags);
}
#endif

#if !HAVE_EXECVEAT
int missing_execveat(int dirfd, const char *pathname, char * const argv[], char * const envp[], int flags) {
        return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
}
#endif
