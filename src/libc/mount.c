/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef fsopen
extern typeof(fsopen_shim) fsopen __attribute__((weak));
int fsopen_shim(const char *fsname, unsigned flags) {
        if (fsopen)
                return fsopen(fsname, flags);
        return syscall(__NR_fsopen, fsname, flags);
}

#undef fsmount
extern typeof(fsmount_shim) fsmount __attribute__((weak));
int fsmount_shim(int fd, unsigned flags, unsigned ms_flags) {
        if (fsmount)
                return fsmount(fd, flags, ms_flags);
        return syscall(__NR_fsmount, fd, flags, ms_flags);
}

#undef move_mount
extern typeof(move_mount_shim) move_mount __attribute__((weak));
int move_mount_shim(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned flags) {
        if (move_mount)
                return move_mount(from_dfd, from_pathname, to_dfd, to_pathname, flags);
        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}

#undef fsconfig
extern typeof(fsconfig_shim) fsconfig __attribute__((weak));
int fsconfig_shim(int fd, unsigned cmd, const char *key, const void *value, int aux) {
        if (fsconfig)
                return fsconfig(fd, cmd, key, value, aux);
        return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

#undef open_tree
extern typeof(open_tree_shim) open_tree __attribute__((weak));
int open_tree_shim(int dfd, const char *filename, unsigned flags) {
        if (open_tree)
                return open_tree(dfd, filename, flags);
        return syscall(__NR_open_tree, dfd, filename, flags);
}

#undef mount_setattr
extern typeof(mount_setattr_shim) mount_setattr __attribute__((weak));
int mount_setattr_shim(int dfd, const char *path, unsigned flags, struct mount_attr *attr, size_t size) {
        if (mount_setattr)
                return mount_setattr(dfd, path, flags, attr, size);
        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

#undef open_tree_attr
extern typeof(open_tree_attr_shim) open_tree_attr __attribute__((weak));
int open_tree_attr_shim(int dfd, const char *filename, unsigned int flags, struct mount_attr *attr, size_t size) {
        if (open_tree_attr)
                return open_tree_attr(dfd, filename, flags, attr, size);
        return syscall(__NR_open_tree_attr, dfd, filename, flags, attr, size);
}
