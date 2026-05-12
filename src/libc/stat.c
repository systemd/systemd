/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef fchmodat2
extern typeof(fchmodat2_shim) fchmodat2 __attribute__((weak));
int fchmodat2_shim(int dirfd, const char *path, mode_t mode, int flags) {
        if (fchmodat2)
                return fchmodat2(dirfd, path, mode, flags);
        return syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}
