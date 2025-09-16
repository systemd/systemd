/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_PIVOT_ROOT
int missing_pivot_root(const char *new_root, const char *put_old) {
        return syscall(__NR_pivot_root, new_root, put_old);
}
#endif
