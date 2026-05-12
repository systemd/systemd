/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioprio.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef ioprio_get
extern typeof(ioprio_get_shim) ioprio_get __attribute__((weak));
int ioprio_get_shim(int which, int who) {
        if (ioprio_get)
                return ioprio_get(which, who);
        return syscall(__NR_ioprio_get, which, who);
}

#undef ioprio_set
extern typeof(ioprio_set_shim) ioprio_set __attribute__((weak));
int ioprio_set_shim(int which, int who, int ioprio) {
        if (ioprio_set)
                return ioprio_set(which, who, ioprio);
        return syscall(__NR_ioprio_set, which, who, ioprio);
}
