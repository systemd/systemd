/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_SCHED_SETATTR
int missing_sched_setattr(pid_t pid, struct sched_attr *attr, unsigned flags) {
        return syscall(__NR_sched_setattr, pid, attr, flags);
}
#endif
