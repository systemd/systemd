/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_RT_TGSIGQUEUEINFO
int missing_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
        return syscall(__NR_rt_tgsigqueueinfo, tgid, tid, sig, info);
}
#endif
