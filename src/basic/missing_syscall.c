/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Missing glibc definitions to access certain kernel APIs */

#include <sched.h>
#include <sys/mount.h>
#include <sys/pidfd.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

/* ======================================================================= */

#if !HAVE_FCHMODAT2
/* since kernel v6.6 (78252deb023cf0879256fcfbafe37022c390762b) */
int fchmodat2(int dirfd, const char *path, mode_t mode, int flags) {
        return syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}
#endif

/* ======================================================================= */

#if !HAVE_PIVOT_ROOT
int pivot_root(const char *new_root, const char *put_old) {
        return syscall(__NR_pivot_root, new_root, put_old);
}
#endif

/* ======================================================================= */

#if !HAVE_PIDFD_SEND_SIGNAL
/* since kernel v5.1 (3eb39f47934f9d5a3027fe00d906a45fe3a15fad) */
int pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
}
#endif

/* ======================================================================= */

#if !HAVE_PIDFD_OPEN
/* since kernel v5.3 (7615d9e1780e26e0178c93c55b73309a5dc093d7) */
int pidfd_open(pid_t pid, unsigned flags) {
        return syscall(__NR_pidfd_open, pid, flags);
}
#endif

/* ======================================================================= */

#if !HAVE_EXECVEAT
/* since kernel v3.19 (51f39a1f0cea1cacf8c787f652f26dfee9611874) */
int execveat(int dirfd, const char *pathname,
                                   char *const argv[], char *const envp[],
                                   int flags) {
        return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
}
#endif

/* ======================================================================= */

#if !HAVE_CLOSE_RANGE
/* since kernel v5.9 (9b4feb630e8e9801603f3cab3a36369e3c1cf88d) */
int close_range(unsigned first_fd, unsigned end_fd, unsigned flags) {
        /* Kernel-side the syscall expects fds as unsigned integers (just like close() actually), while
         * userspace exclusively uses signed integers for fds. glibc chose to expose it 1:1 however, hence we
         * do so here too, even if we end up passing signed fds to it most of the time. */
        return syscall(__NR_close_range,
                       first_fd,
                       end_fd,
                       flags);
}
#endif

/* ======================================================================= */

#if !HAVE_SCHED_SETATTR
/* since kernel 3.14 (e6cfc0295c7d51b008999a8b13a44fb43f8685ea) */
int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags) {
        return syscall(__NR_sched_setattr, pid, attr, flags);
}
#endif

/* ======================================================================= */

#if !HAVE_QUOTACTL_FD
/* since kernel v5.14 (64c2c2c62f92339b176ea24403d8db16db36f9e6) */
int quotactl_fd(int fd, int cmd, int id, void *addr) {
        return syscall(__NR_quotactl_fd, fd, cmd, id, addr);
}
#endif

/* ======================================================================= */

#if !HAVE_SETXATTRAT
/* since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394) */
int setxattrat(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size) {
        return syscall(__NR_setxattrat, fd, path, at_flags, name, args, size);
}
#endif

/* ======================================================================= */

#if !HAVE_REMOVEXATTRAT
/* since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394) */
int removexattrat(int fd, const char *path, int at_flags, const char *name) {
        return syscall(__NR_removexattrat, fd, path, at_flags, name);
}
#endif

/* ======================================================================= */

#if !HAVE_FSOPEN
int fsopen(const char *__fs_name, unsigned int __flags) {
        return syscall(__NR_fsopen, __fs_name, __flags);
}
#endif

/* ======================================================================= */

#if !HAVE_FSMOUNT
int fsmount(int __fd, unsigned int __flags, unsigned int __ms_flags) {
        return syscall(__NR_fsmount, __fd, __flags, __ms_flags);
}
#endif

/* ======================================================================= */

#if !HAVE_MOVE_MOUNT
int move_mount(int __from_dfd, const char *__from_pathname, int __to_dfd, const char *__to_pathname, unsigned int __flags) {
        return syscall(__NR_move_mount, __from_dfd, __from_pathname, __to_dfd, __to_pathname, __flags);
}
#endif

/* ======================================================================= */

#if !HAVE_FSCONFIG
int fsconfig(int __fd, unsigned int __cmd, const char *__key, const void *__value, int __aux) {
        return syscall(__NR_fsconfig, __fd, __cmd, __key, __value, __aux);
}
#endif

/* ======================================================================= */

#if !HAVE_OPEN_TREE
int open_tree(int __dfd, const char *__filename, unsigned int __flags) {
        return syscall(__NR_open_tree, __dfd, __filename, __flags);
}
#endif

/* ======================================================================= */

#if !HAVE_MOUNT_SETATTR
int mount_setattr(int __dfd, const char *__path, unsigned int __flags, struct mount_attr *__attr, size_t __size) {
        return syscall(__NR_mount_setattr, __dfd, __path, __flags, __attr, __size);
#endif
