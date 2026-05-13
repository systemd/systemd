/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_FCHMODAT2
int missing_fchmodat2(int dirfd, const char *path, mode_t mode, int flags) {
        return syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}
#endif
