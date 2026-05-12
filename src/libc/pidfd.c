/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/pidfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef pidfd_open
extern typeof(pidfd_open_shim) pidfd_open __attribute__((weak));
int pidfd_open_shim(pid_t pid, unsigned flags) {
        if (pidfd_open)
                return pidfd_open(pid, flags);
        return syscall(__NR_pidfd_open, pid, flags);
}

#undef pidfd_send_signal
extern typeof(pidfd_send_signal_shim) pidfd_send_signal __attribute__((weak));
int pidfd_send_signal_shim(int fd, int sig, siginfo_t *info, unsigned flags) {
        if (pidfd_send_signal)
                return pidfd_send_signal(fd, sig, info, flags);
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
}
