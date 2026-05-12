/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef rt_tgsigqueueinfo
extern typeof(missing_rt_tgsigqueueinfo) rt_tgsigqueueinfo;
#pragma weak rt_tgsigqueueinfo
int missing_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
        if (rt_tgsigqueueinfo)
                return rt_tgsigqueueinfo(tgid, tid, sig, info);
        return syscall(__NR_rt_tgsigqueueinfo, tgid, tid, sig, info);
}
