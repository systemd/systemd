/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioprio.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef ioprio_get
extern typeof(missing_ioprio_get) ioprio_get;
#pragma weak ioprio_get
int missing_ioprio_get(int which, int who) {
        if (ioprio_get)
                return ioprio_get(which, who);
        return syscall(__NR_ioprio_get, which, who);
}

#undef ioprio_set
extern typeof(missing_ioprio_set) ioprio_set;
#pragma weak ioprio_set
int missing_ioprio_set(int which, int who, int ioprio) {
        if (ioprio_set)
                return ioprio_set(which, who, ioprio);
        return syscall(__NR_ioprio_set, which, who, ioprio);
}
