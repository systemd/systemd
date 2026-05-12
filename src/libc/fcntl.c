/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef openat2
extern typeof(missing_openat2) openat2;
#pragma weak openat2
int missing_openat2(int dfd, const char *filename, const struct open_how *how, size_t usize) {
        if (openat2)
                return openat2(dfd, filename, how, usize);
        return syscall(__NR_openat2, dfd, filename, how, usize);
}
