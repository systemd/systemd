/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/pidfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef pidfd_open
extern typeof(missing_pidfd_open) pidfd_open;
#pragma weak pidfd_open
int missing_pidfd_open(pid_t pid, unsigned flags) {
        if (pidfd_open)
                return pidfd_open(pid, flags);
        return syscall(__NR_pidfd_open, pid, flags);
}

#undef pidfd_send_signal
extern typeof(missing_pidfd_send_signal) pidfd_send_signal;
#pragma weak pidfd_send_signal
int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
        if (pidfd_send_signal)
                return pidfd_send_signal(fd, sig, info, flags);
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
}
