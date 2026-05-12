/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef openat2
extern typeof(openat2_shim) openat2 __attribute__((weak));
int openat2_shim(int dfd, const char *filename, const struct open_how *how, size_t usize) {
        if (openat2)
                return openat2(dfd, filename, how, usize);
        return syscall(__NR_openat2, dfd, filename, how, usize);
}
