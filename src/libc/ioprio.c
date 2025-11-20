/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioprio.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_IOPRIO_GET
int missing_ioprio_get(int which, int who) {
        return syscall(__NR_ioprio_get, which, who);
}
#endif

#if !HAVE_IOPRIO_SET
int missing_ioprio_set(int which, int who, int ioprio) {
        return syscall(__NR_ioprio_set, which, who, ioprio);
}
#endif
