/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_FSOPEN
int missing_fsopen(const char *fsname, unsigned flags) {
        return syscall(__NR_fsopen, fsname, flags);
}
#endif

#if !HAVE_FSMOUNT
int missing_fsmount(int fd, unsigned flags, unsigned ms_flags) {
        return syscall(__NR_fsmount, fd, flags, ms_flags);
}
#endif

#if !HAVE_MOVE_MOUNT
int missing_move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned flags) {
        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}
#endif

#if !HAVE_FSCONFIG
int missing_fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux) {
        return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
#endif

#if !HAVE_OPEN_TREE
int missing_open_tree(int dfd, const char *filename, unsigned flags) {
        return syscall(__NR_open_tree, dfd, filename, flags);
}
#endif

#if !HAVE_MOUNT_SETATTR
int missing_mount_setattr(int dfd, const char *path, unsigned flags, struct mount_attr *attr, size_t size) {
        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}
#endif

#if !HAVE_OPEN_TREE_ATTR
int missing_open_tree_attr(int dfd, const char *filename, unsigned int flags, struct mount_attr *attr, size_t size) {
        return syscall(__NR_open_tree_attr, dfd, filename, flags, attr, size);
}
#endif
