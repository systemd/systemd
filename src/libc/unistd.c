/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syscall.h>
#include <unistd.h>

#undef pivot_root
extern typeof(missing_pivot_root) pivot_root __attribute__((weak));
int missing_pivot_root(const char *new_root, const char *put_old) {
        if (pivot_root)
                return pivot_root(new_root, put_old);
        return syscall(__NR_pivot_root, new_root, put_old);
}
