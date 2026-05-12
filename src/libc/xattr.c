/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#undef setxattrat
extern typeof(setxattrat_shim) setxattrat __attribute__((weak));
int setxattrat_shim(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size) {
        if (setxattrat)
                return setxattrat(fd, path, at_flags, name, args, size);
        return syscall(__NR_setxattrat, fd, path, at_flags, name, args, size);
}

#undef removexattrat
extern typeof(removexattrat_shim) removexattrat __attribute__((weak));
int removexattrat_shim(int fd, const char *path, int at_flags, const char *name) {
        if (removexattrat)
                return removexattrat(fd, path, at_flags, name);
        return syscall(__NR_removexattrat, fd, path, at_flags, name);
}
