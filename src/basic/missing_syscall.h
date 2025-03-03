/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <linux/time_types.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#include "macro.h"
#include "missing_keyctl.h"
#include "missing_sched.h"
#include "missing_syscall_def.h"

/* ======================================================================= */

#if !HAVE_FCHMODAT2
/* since kernel v6.6 (78252deb023cf0879256fcfbafe37022c390762b) */
static inline int missing_fchmodat2(int dirfd, const char *path, mode_t mode, int flags) {
        return syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}

#  define fchmodat2 missing_fchmodat2
#endif

/* ======================================================================= */

#if !HAVE_PIVOT_ROOT
static inline int missing_pivot_root(const char *new_root, const char *put_old) {
        return syscall(__NR_pivot_root, new_root, put_old);
}

#  define pivot_root missing_pivot_root
#endif

/* ======================================================================= */

#if !HAVE_IOPRIO_GET
static inline int missing_ioprio_get(int which, int who) {
        return syscall(__NR_ioprio_get, which, who);
}

#  define ioprio_get missing_ioprio_get
#endif

/* ======================================================================= */

#if !HAVE_IOPRIO_SET
static inline int missing_ioprio_set(int which, int who, int ioprio) {
        return syscall(__NR_ioprio_set, which, who, ioprio);
}

#  define ioprio_set missing_ioprio_set
#endif

/* ======================================================================= */

static inline pid_t raw_getpid(void) {
#if defined(__alpha__)
        return (pid_t) syscall(__NR_getxpid);
#else
        return (pid_t) syscall(__NR_getpid);
#endif
}

/* ======================================================================= */

#if !HAVE_KCMP
static inline int missing_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
}

#  define kcmp missing_kcmp
#endif

/* ======================================================================= */

#if !HAVE_KEYCTL
static inline long missing_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);

#  define keyctl missing_keyctl
}

/* ======================================================================= */

static inline key_serial_t missing_add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
        return syscall(__NR_add_key, type, description, payload, plen, ringid);

#  define add_key missing_add_key
}

/* ======================================================================= */

static inline key_serial_t missing_request_key(const char *type, const char *description, const char * callout_info, key_serial_t destringid) {
        return syscall(__NR_request_key, type, description, callout_info, destringid);

#  define request_key missing_request_key
}
#endif

/* ======================================================================= */

#if !HAVE_BPF
union bpf_attr;

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size) {
        return (int) syscall(__NR_bpf, cmd, attr, size);
}

#  define bpf missing_bpf
#endif

/* ======================================================================= */

#if !HAVE_SET_MEMPOLICY
enum {
        MPOL_DEFAULT,
        MPOL_PREFERRED,
        MPOL_BIND,
        MPOL_INTERLEAVE,
        MPOL_LOCAL,
};

static inline long missing_set_mempolicy(int mode, const unsigned long *nodemask,
                           unsigned long maxnode) {
        return syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
}

#  define set_mempolicy missing_set_mempolicy
#endif

#if !HAVE_GET_MEMPOLICY
static inline long missing_get_mempolicy(int *mode, unsigned long *nodemask,
                           unsigned long maxnode, void *addr,
                           unsigned long flags) {
        return syscall(__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}

#  define get_mempolicy missing_get_mempolicy
#endif

/* ======================================================================= */

#if !HAVE_PIDFD_SEND_SIGNAL
/* since kernel v5.1 (3eb39f47934f9d5a3027fe00d906a45fe3a15fad) */
static inline int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
}

#  define pidfd_send_signal missing_pidfd_send_signal
#endif

/* ======================================================================= */

#if !HAVE_PIDFD_OPEN
/* since kernel v5.3 (7615d9e1780e26e0178c93c55b73309a5dc093d7) */
static inline int missing_pidfd_open(pid_t pid, unsigned flags) {
        return syscall(__NR_pidfd_open, pid, flags);
}

#  define pidfd_open missing_pidfd_open
#endif

/* ======================================================================= */

#if !HAVE_RT_TGSIGQUEUEINFO
static inline int missing_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
        return syscall(__NR_rt_tgsigqueueinfo, tgid, tid, sig, info);
}

#  define rt_tgsigqueueinfo missing_rt_tgsigqueueinfo
#endif

/* ======================================================================= */

#if !HAVE_EXECVEAT
/* since kernel v3.19 (51f39a1f0cea1cacf8c787f652f26dfee9611874) */
static inline int missing_execveat(int dirfd, const char *pathname,
                                   char *const argv[], char *const envp[],
                                   int flags) {
        return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
}

#  undef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#  define execveat missing_execveat
#endif

/* ======================================================================= */

#if !HAVE_CLOSE_RANGE
/* since kernel v5.9 (9b4feb630e8e9801603f3cab3a36369e3c1cf88d) */
static inline int missing_close_range(unsigned first_fd, unsigned end_fd, unsigned flags) {
        /* Kernel-side the syscall expects fds as unsigned integers (just like close() actually), while
         * userspace exclusively uses signed integers for fds. glibc chose to expose it 1:1 however, hence we
         * do so here too, even if we end up passing signed fds to it most of the time. */
        return syscall(__NR_close_range,
                       first_fd,
                       end_fd,
                       flags);
}

#  define close_range missing_close_range
#endif

/* ======================================================================= */

#if !HAVE_MOUNT_SETATTR
/* since kernel v5.12 (2a1867219c7b27f928e2545782b86daaf9ad50bd) */

#if !HAVE_STRUCT_MOUNT_ATTR
struct mount_attr {
        uint64_t attr_set;
        uint64_t attr_clr;
        uint64_t propagation;
        uint64_t userns_fd;
};
#else
struct mount_attr;
#endif

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY       0x00000001 /* Mount read-only */
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID       0x00000002 /* Ignore suid and sgid bits */
#endif

#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV        0x00000004 /* Disallow access to device special files */
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC       0x00000008 /* Disallow program execution */
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME       0x00000070 /* Setting on how atime should be updated */
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME     0x00000000 /* - Update atime relative to mtime/ctime. */
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME      0x00000010 /* - Do not update access times. */
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME  0x00000020 /* - Always perform atime updates */
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME   0x00000080 /* Do not update directory access times */
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP        0x00100000 /* Idmap mount to @userns_fd in struct mount_attr. */
#endif

#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW  0x00200000 /* Do not follow symlinks */
#endif

#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0    32 /* sizeof first published struct */
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

static inline int missing_mount_setattr(
                int dfd,
                const char *path,
                unsigned flags,
                struct mount_attr *attr,
                size_t size) {

        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

#  define mount_setattr missing_mount_setattr
#endif

/* ======================================================================= */

#if !HAVE_OPEN_TREE
/* since kernel v5.2 (a07b20004793d8926f78d63eb5980559f7813404, d8076bdb56af5e5918376cd1573a6b0007fc1a89) */

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

static inline int missing_open_tree(
                int dfd,
                const char *filename,
                unsigned flags) {

        return syscall(__NR_open_tree, dfd, filename, flags);
}

#  define open_tree missing_open_tree
#endif

/* ======================================================================= */

#ifndef MOVE_MOUNT_BENEATH
#define MOVE_MOUNT_BENEATH 0x00000200
#endif

#if !HAVE_MOVE_MOUNT
/* since kernel v5.2 (2db154b3ea8e14b04fee23e3fdfd5e9d17fbc6ae, d8076bdb56af5e5918376cd1573a6b0007fc1a89) */

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#endif

static inline int missing_move_mount(
                int from_dfd,
                const char *from_pathname,
                int to_dfd,
                const char *to_pathname,
                unsigned flags) {

        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}

#  define move_mount missing_move_mount
#endif

/* ======================================================================= */

#if !HAVE_FSOPEN
/* since kernel v5.2 (24dcb3d90a1f67fe08c68a004af37df059d74005, d8076bdb56af5e5918376cd1573a6b0007fc1a89) */

#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

static inline int missing_fsopen(const char *fsname, unsigned flags) {
        return syscall(__NR_fsopen, fsname, flags);
}

#  define fsopen missing_fsopen
#endif

/* ======================================================================= */

#if !HAVE_FSCONFIG
/* since kernel v5.2 (ecdab150fddb42fe6a739335257949220033b782, d8076bdb56af5e5918376cd1573a6b0007fc1a89) */

#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG 0 /* Set parameter, supplying no value */
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1 /* Set parameter, supplying a string value */
#endif

#ifndef FSCONFIG_SET_FD
#define FSCONFIG_SET_FD 5 /* Set parameter, supplying an object by fd */
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6 /* Invoke superblock creation */
#endif

static inline int missing_fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux) {
        return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

#  define fsconfig missing_fsconfig
#endif

/* ======================================================================= */

#if !HAVE_FSMOUNT
/* since kernel v5.2 for (93766fbd2696c2c4453dd8e1070977e9cd4e6b6d, d8076bdb56af5e5918376cd1573a6b0007fc1a89) */

#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x00000001
#endif

static inline int missing_fsmount(int fd, unsigned flags, unsigned ms_flags) {
        return syscall(__NR_fsmount, fd, flags, ms_flags);
}

#  define fsmount missing_fsmount
#endif

/* ======================================================================= */

#if !HAVE_GETDENTS64
static inline ssize_t missing_getdents64(int fd, void *buffer, size_t length) {
        return syscall(__NR_getdents64, fd, buffer, length);
}

#  define getdents64 missing_getdents64
#endif

/* ======================================================================= */

#if !HAVE_SCHED_SETATTR
/* since kernel 3.14 (e6cfc0295c7d51b008999a8b13a44fb43f8685ea) */
static inline ssize_t missing_sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags) {
        return syscall(__NR_sched_setattr, pid, attr, flags);
}

#  define sched_setattr missing_sched_setattr
#endif

/* ======================================================================= */

/* glibc does not provide clone() on ia64, only clone2(). Not only that, but it also doesn't provide a
 * prototype, only the symbol in the shared library (it provides a prototype for clone(), but not the
 * symbol in the shared library). */
#if defined(__ia64__)
int __clone2(int (*fn)(void *), void *stack_base, size_t stack_size, int flags, void *arg);
#define HAVE_CLONE 0
#else
/* We know that everywhere else clone() is available, so we don't bother with a meson check (that takes time
 * at build time) and just define it. Once the kernel drops ia64 support, we can drop this too. */
#define HAVE_CLONE 1
#endif

/* ======================================================================= */

#if !HAVE_QUOTACTL_FD
/* since kernel v5.14 (64c2c2c62f92339b176ea24403d8db16db36f9e6) */
static inline int missing_quotactl_fd(int fd, int cmd, int id, void *addr) {
        return syscall(__NR_quotactl_fd, fd, cmd, id, addr);
}

#  define quotactl_fd missing_quotactl_fd
#endif

/* ======================================================================= */

#if !HAVE_SETXATTRAT
/* since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394) */
struct xattr_args {
        _align_(8) uint64_t value;
        uint32_t size;
        uint32_t flags;
};

static inline int missing_setxattrat(int fd, const char *path, int at_flags, const char *name, const struct xattr_args *args, size_t size) {
        return syscall(__NR_setxattrat, fd, path, at_flags, name, args, size);
}

#  define setxattrat missing_setxattrat
#endif

/* ======================================================================= */

#if !HAVE_REMOVEXATTRAT
/* since kernel v6.13 (6140be90ec70c39fa844741ca3cc807dd0866394) */
static inline int missing_removexattrat(int fd, const char *path, int at_flags, const char *name) {
        return syscall(__NR_removexattrat, fd, path, at_flags, name);
}

#  define removexattrat missing_removexattrat
#endif
