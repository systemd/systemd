/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/kcmp.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef kcmp
extern typeof(kcmp_shim) kcmp __attribute__((weak));
int kcmp_shim(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
        if (kcmp)
                return kcmp(pid1, pid2, type, idx1, idx2);
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
}
