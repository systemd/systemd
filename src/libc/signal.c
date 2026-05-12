/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef rt_tgsigqueueinfo
extern typeof(rt_tgsigqueueinfo_shim) rt_tgsigqueueinfo __attribute__((weak));
int rt_tgsigqueueinfo_shim(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
        if (rt_tgsigqueueinfo)
                return rt_tgsigqueueinfo(tgid, tid, sig, info);
        return syscall(__NR_rt_tgsigqueueinfo, tgid, tid, sig, info);
}
