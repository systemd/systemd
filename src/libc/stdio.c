/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_RENAMEAT2
int missing_renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned __flags) {
        return syscall(__NR_renameat2, __oldfd, __old, __newfd, __new, __flags);
}
#endif
