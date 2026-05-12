/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef sched_setattr
extern typeof(missing_sched_setattr) sched_setattr;
#pragma weak sched_setattr
int missing_sched_setattr(pid_t pid, struct sched_attr *attr, unsigned flags) {
        if (sched_setattr)
                return sched_setattr(pid, attr, flags);
        return syscall(__NR_sched_setattr, pid, attr, flags);
}
