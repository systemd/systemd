/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef fsopen
extern typeof(missing_fsopen) fsopen;
#pragma weak fsopen
int missing_fsopen(const char *fsname, unsigned flags) {
        if (fsopen)
                return fsopen(fsname, flags);
        return syscall(__NR_fsopen, fsname, flags);
}

#undef fsmount
extern typeof(missing_fsmount) fsmount;
#pragma weak fsmount
int missing_fsmount(int fd, unsigned flags, unsigned ms_flags) {
        if (fsmount)
                return fsmount(fd, flags, ms_flags);
        return syscall(__NR_fsmount, fd, flags, ms_flags);
}

#undef move_mount
extern typeof(missing_move_mount) move_mount;
#pragma weak move_mount
int missing_move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned flags) {
        if (move_mount)
                return move_mount(from_dfd, from_pathname, to_dfd, to_pathname, flags);
        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}

#undef fsconfig
extern typeof(missing_fsconfig) fsconfig;
#pragma weak fsconfig
int missing_fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux) {
        if (fsconfig)
                return fsconfig(fd, cmd, key, value, aux);
        return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

#undef open_tree
extern typeof(missing_open_tree) open_tree;
#pragma weak open_tree
int missing_open_tree(int dfd, const char *filename, unsigned flags) {
        if (open_tree)
                return open_tree(dfd, filename, flags);
        return syscall(__NR_open_tree, dfd, filename, flags);
}

#undef mount_setattr
extern typeof(missing_mount_setattr) mount_setattr;
#pragma weak mount_setattr
int missing_mount_setattr(int dfd, const char *path, unsigned flags, struct mount_attr *attr, size_t size) {
        if (mount_setattr)
                return mount_setattr(dfd, path, flags, attr, size);
        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

#undef open_tree_attr
extern typeof(missing_open_tree_attr) open_tree_attr;
#pragma weak open_tree_attr
int missing_open_tree_attr(int dfd, const char *filename, unsigned int flags, struct mount_attr *attr, size_t size) {
        if (open_tree_attr)
                return open_tree_attr(dfd, filename, flags, attr, size);
        return syscall(__NR_open_tree_attr, dfd, filename, flags, attr, size);
}
