/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_OPENAT2
int missing_openat2(int dfd, const char *filename, const struct open_how *how, size_t usize) {
        return syscall(__NR_openat2, dfd, filename, how, usize);
}
#endif
