/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef fchmodat2
extern typeof(missing_fchmodat2) fchmodat2;
#pragma weak fchmodat2
int missing_fchmodat2(int dirfd, const char *path, mode_t mode, int flags) {
        if (fchmodat2)
                return fchmodat2(dirfd, path, mode, flags);
        return syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}
